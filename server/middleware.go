package server

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/kdwils/envoy-proxy-gatekeeper/logger"
	"github.com/kdwils/envoy-proxy-gatekeeper/pkg/cache"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

func (s Server) LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := s.logger.With("method", r.Method, "path", r.URL.Path)
		ctx := logger.WithContext(r.Context(), log)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) loggerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	log := s.logger.With("grpc.method", info.FullMethod)
	ctx = logger.WithContext(ctx, log)
	return handler(ctx, req)
}

type RateLimiter struct {
	visitors       *cache.Cache[string, *rate.Limiter]
	mu             sync.Mutex
	rate           rate.Limit
	burst          int
	ip             func(ip string, headers map[string][]string, trustedProxies []*net.IPNet) string
	trustedProxies []*net.IPNet
}

func NewRateLimiter(r rate.Limit, b int, opts ...RateLimiterOpt) *RateLimiter {
	rl := &RateLimiter{
		visitors: cache.New[string, *rate.Limiter](),
		rate:     r,
		burst:    b,
	}

	for _, opt := range opts {
		opt(rl)
	}

	return rl
}

type RateLimiterOpt func(r *RateLimiter)

func WithTrustedProxies(proxies []*net.IPNet) func(r *RateLimiter) {
	return func(r *RateLimiter) {
		r.trustedProxies = proxies
	}
}

func WithRealIp(ip func(ip string, headers map[string][]string, trustedProxies []*net.IPNet) string) func(r *RateLimiter) {
	return func(r *RateLimiter) {
		r.ip = ip
	}
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	limiter, exists := rl.visitors.Get(key)
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors.Set(key, limiter)
	}
	return limiter
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if rl.ip != nil {
			ip = rl.ip(r.RemoteAddr, r.Header, rl.trustedProxies)
		}

		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
