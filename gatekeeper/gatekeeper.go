package gatekeeper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strings"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kdwils/envoy-proxy-gatekeeper/logger"
	"github.com/kdwils/envoy-proxy-gatekeeper/pkg/jwt"
)

// TokenService defines the behavior for issuing and verifying tokens
type TokenService interface {
	CreateChallengeToken(originalURL, remoteIP string) (string, *jwt.ChallengeClaims, error)
	CheckChallengeToken(tokenString string) (*jwt.ChallengeClaims, error)
	VerifyResponse(ctx context.Context, ip, challengeToken, challengeResponse string) (*jwt.ChallengeClaims, error)
	NewSession(challenge *jwt.ChallengeClaims) *jwt.Session
	CreateSessionToken(session *jwt.Session) (string, error)
	VerifySessionToken(tokenString string) (*jwt.SessionClaims, error)
	WriteSessionCookie(w http.ResponseWriter, token string)
	Provider() (name string, siteKey string)
}

type Gatekeeper struct {
	tokenService   TokenService
	trustedProxies []*net.IPNet
}

func New(tokenService TokenService, trustedProxies []*net.IPNet) Gatekeeper {
	return Gatekeeper{
		tokenService:   tokenService,
		trustedProxies: trustedProxies,
	}
}

type Challenge struct {
	Challenge       ChallengeRequest
	ProviderName    string `json:"-"`
	ProviderSiteKey string `json:"-"`
}

type ChallengeRequest struct {
	ProviderName    string
	ProviderSiteKey string
	Token           string
}

func (g Gatekeeper) HandleCaptchaChallenge(ctx context.Context, req *http.Request) (ChallengeRequest, error) {
	var request ChallengeRequest

	ip := ExtractRealIP(req.RemoteAddr, req.Header, g.trustedProxies)

	token, _, err := g.tokenService.CreateChallengeToken("/", ip)
	if err != nil {
		return request, err
	}

	provider, siteKey := g.tokenService.Provider()

	request.ProviderName = provider
	request.ProviderSiteKey = siteKey
	request.Token = token

	return request, nil
}

// VerificationResult result of the challenge verification. Session will be nil if failed
type VerificationResult struct {
	Success bool
	Session *jwt.Session
	Token   string
	Err     error
	Message string
}

type VerificationRequest struct {
	Token    string `json:"token"`
	Response string `json:"response"`
}

func (g Gatekeeper) VerifyChallenge(ctx context.Context, req *http.Request) (VerificationResult, error) {
	log := logger.FromContext(ctx)
	defaultResult := VerificationResult{
		Success: false,
	}

	if err := req.ParseForm(); err != nil {
		log.Error("failed to parse form data", "error", err)
		return defaultResult, err
	}

	challengeToken := req.FormValue("challengeToken")
	captchaResponse := req.FormValue("captchaResponse")

	headers := make(map[string][]string)
	maps.Copy(headers, req.Header)
	ip := ExtractRealIP(req.RemoteAddr, headers, g.trustedProxies)

	claims, err := g.tokenService.VerifyResponse(ctx, ip, challengeToken, captchaResponse)
	if err != nil {
		if !errors.Is(err, jwt.ErrFailedChallenge) {
			log.Error("failed to verify challenge response", "error", err)
			return defaultResult, fmt.Errorf("failed to verify response: %v", err)
		}

		log.Info("user failed verification challenge")
		return VerificationResult{
			Success: false,
			Message: "Verification failed. Please try again.",
		}, nil
	}

	session := g.tokenService.NewSession(claims)
	token, err := g.tokenService.CreateSessionToken(session)
	if err != nil {
		log.Error("failed to create session token", "error", err)
		return defaultResult, fmt.Errorf("failed to create session token: %v", err)
	}

	log.Debug("user jwt successfully verified", "id", session.ID, "exp", session.ExpiresAt)
	return VerificationResult{
		Success: true,
		Session: session,
		Token:   token,
	}, nil
}

func (g Gatekeeper) WriteSessionCookie(ctx context.Context, w http.ResponseWriter, token string) {
	g.tokenService.WriteSessionCookie(w, token)
}

// VerifySession validates a session token and returns the session if valid
func (g Gatekeeper) VerifySession(ctx context.Context, request *auth.CheckRequest) (*jwt.Session, error) {
	log := logger.FromContext(ctx)
	if request == nil {
		log.Error("received nil check request")
		return nil, fmt.Errorf("auth check request is nil")
	}

	cookie := parseSessionCookie(request)
	if cookie == "" {
		log.Debug("no session cookie present")
		return nil, errors.New("no jwt cookie found")
	}

	claims, err := g.tokenService.VerifySessionToken(cookie)
	if err != nil {
		log.Error("failed to verify session cookie", "error", err)
		return nil, err
	}

	session := &jwt.Session{
		ID:        claims.SID,
		CreatedAt: claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	log.Debug("found claims", "session", session)
	return session, nil
}

func parseSessionCookie(r *auth.CheckRequest) string {
	atts := r.Attributes
	if atts == nil {
		return ""
	}

	request := atts.Request
	if request == nil {
		return ""
	}

	http := request.Http
	if http == nil {
		return ""
	}

	cookie, ok := http.Headers["cookie"]
	if !ok {
		return ""
	}

	cookies := strings.SplitSeq(cookie, ";")
	for c := range cookies {
		if c == "" {
			continue
		}

		c = strings.TrimSpace(c)
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if key == "__Host-session" {
			return value
		}
	}

	return ""
}

func ExtractRealIP(ip string, headers map[string][]string, trustedProxies []*net.IPNet) string {
	if xForwardedFor := headers["X-Forwarded-For"]; len(xForwardedFor) > 0 {
		ips := strings.Split(xForwardedFor[0], ",")
		if len(ips) > 20 {
			ips = ips[len(ips)-20:]
		}

		for i := len(ips) - 1; i >= 0; i-- {
			parsedIP := strings.TrimSpace(ips[i])
			if !isTrustedProxy(parsedIP, trustedProxies) && isValidIP(parsedIP) {
				return parsedIP
			}
		}
	}

	if xRealIP := headers["X-Real-IP"]; len(xRealIP) > 0 && isValidIP(xRealIP[0]) {
		return xRealIP[0]
	}

	return strings.Split(ip, ":")[0]
}

// isTrustedProxy returns true if the IP is in the trusted proxies list.
func isTrustedProxy(ip string, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, net := range trustedProxies {
		if net.Contains(parsed) {
			return true
		}
	}
	return false
}

// isValidIP returns true if the string is a valid IPv4 or IPv6 address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
