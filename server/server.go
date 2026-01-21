package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kdwils/envoy-proxy-gatekeeper/gatekeeper"
	"github.com/kdwils/envoy-proxy-gatekeeper/logger"
	"github.com/kdwils/envoy-proxy-gatekeeper/template"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	logger      *slog.Logger
	gatekeeper  gatekeeper.Gatekeeper
	templates   *template.Store
	rateLimiter *RateLimiter
	host        string
	scheme      string
	httpPort    int
	grpcPort    int
}

func New(logger *slog.Logger, gatekeeper gatekeeper.Gatekeeper, templateStore *template.Store, rl *RateLimiter, scheme, host string, httpPort, grpcPort int) Server {
	return Server{
		scheme:      scheme,
		host:        host,
		logger:      logger,
		gatekeeper:  gatekeeper,
		templates:   templateStore,
		httpPort:    httpPort,
		grpcPort:    grpcPort,
		rateLimiter: rl,
	}
}

// ServeDual starts both gRPC and HTTP servers concurrently
func (s *Server) ServeDual(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Go(func() {
		s.logger.Info("starting gRPC server", "port", s.grpcPort)
		if err := s.serveGRPC(ctx, s.grpcPort); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	})

	wg.Go(func() {
		s.logger.Info("starting http server", "port", s.httpPort)
		if err := s.serveHTTP(ctx, s.httpPort); err != nil {
			errChan <- fmt.Errorf("http server error: %w", err)
		}
	})

	go func() {
		wg.Wait()
		close(errChan)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) serveGRPC(ctx context.Context, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %v", port, err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(s.loggerInterceptor),
	)
	auth.RegisterAuthorizationServer(grpcServer, s)
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down gRPC server...")
		grpcServer.GracefulStop()
		s.logger.Info("gRPC server shutdown complete")
	}()

	s.logger.Info("grpc serving", "addr", lis.Addr().String())
	return grpcServer.Serve(lis)
}

func (s *Server) serveHTTP(ctx context.Context, port int) error {
	r := mux.NewRouter()
	r.HandleFunc("/captcha/verify", s.handleCaptchaVerify()).Methods(http.MethodPost, http.MethodGet, http.MethodOptions)
	r.HandleFunc("/captcha/challenge", s.handleCaptchaChallenge()).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/healthz", s.Healthz()).Methods(http.MethodGet)
	r.Use(s.LoggerMiddleware)

	handler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{http.MethodPost, http.MethodGet, http.MethodOptions}),
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)(r)

	if s.rateLimiter != nil {
		handler = s.rateLimiter.Middleware(handler)
	}

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		s.logger.Info("context canceled: terminating http server")
		httpServer.Shutdown(context.Background())
	}()

	s.logger.Info("http serving", "addr", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to serve http: %v", err)
	}
	return nil
}

func (s *Server) handleCaptchaChallenge() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, err := s.gatekeeper.HandleCaptchaChallenge(r.Context(), r)
		if err != nil {
			http.Error(w, "failed to create captcha challenge", http.StatusInternalServerError)
			return
		}

		callback := url.URL{
			Scheme: s.scheme,
			Host:   s.host,
			Path:   "/captcha/verify",
		}

		pageData := template.ChallengePageData{
			Provider:       request.ProviderName,
			SiteKey:        request.ProviderSiteKey,
			ChallengeToken: request.Token,
			CallbackURL:    callback.String(),
		}

		s.templates.RenderCaptcha(w, pageData)
	}
}

func (s *Server) handleCaptchaVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log := logger.FromContext(ctx)
		result, err := s.gatekeeper.VerifyChallenge(ctx, r)
		if err != nil {
			log.Error("failed to verify challenge", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !result.Success {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		s.gatekeeper.WriteSessionCookie(ctx, w, result.Token)
		http.Redirect(w, r, result.Session.OriginalURL, http.StatusFound)
	}
}

func (s *Server) Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// Server implements the Envoy Authorization gRPC interface
func (s *Server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	_, err := s.gatekeeper.VerifySession(ctx, req)
	if err == nil {
		return getAllowedResponse(), nil
	}

	challenge := url.URL{
		Scheme: s.scheme,
		Host:   s.host,
		Path:   "/captcha/challenge",
	}

	return getRedirectResponse(challenge.String()), nil
}

func getAllowedResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: 0,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{},
	}
}

func getRedirectResponse(location string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(envoy_type.StatusCode_Found),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*envoy_core.HeaderValueOption{
					{
						Header: &envoy_core.HeaderValue{
							Key:   "Location",
							Value: location,
						},
					},
				},
			},
		},
	}
}
