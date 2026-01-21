package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kdwils/envoy-proxy-gatekeeper/pkg/cache"
)

var (
	// ErrFailedVerification indicates the challenge was not successfully completed
	ErrFailedChallenge = errors.New("challenge verification failed")
)

type Service struct {
	signingKey     []byte
	siteKey        string
	provider       Provider
	now            func() time.Time
	timeout        time.Duration
	sessionTTL     time.Duration
	challengeTTL   time.Duration
	challengeCache *cache.Cache[string, ChallengeClaims]
	cookieDomain   string
	cookieName     string
}

type ChallengeClaims struct {
	IPHash      string `json:"ip"`
	OriginalURL string `json:"ou"`
	jwt.RegisteredClaims
}

type SessionClaims struct {
	SID string `json:"sid"`
	jwt.RegisteredClaims
}

type Session struct {
	IP           string
	ID           string
	Provider     string
	OriginalURL  string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	SiteKey      string
	CallbackURL  string
	RedirectURL  string
	ChallengeURL string
}

type VerificationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type Provider interface {
	Name() string
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
}

func NewService(provider Provider, signingKey, siteKey, cookieDomain, cookieName string, timeout time.Duration, challengeTtl, sessionTtl time.Duration) Service {
	if cookieName == "" {
		cookieName = "__Host-session"
	}
	cache := cache.New[string, ChallengeClaims]()
	return Service{
		signingKey:     []byte(signingKey),
		siteKey:        siteKey,
		provider:       provider,
		now:            time.Now,
		challengeCache: cache,
		timeout:        timeout,
		challengeTTL:   challengeTtl,
		sessionTTL:     sessionTtl,
	}
}

func (s *Service) CreateChallengeToken(originalURL, remoteIP string) (string, *ChallengeClaims, error) {
	claims := ChallengeClaims{
		IPHash:      s.ipHashKey(remoteIP),
		OriginalURL: originalURL,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(s.now()),
			ExpiresAt: jwt.NewNumericDate(s.now().Add(s.challengeTTL)),
		},
	}

	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign challenge token: %w", err)
	}

	s.challengeCache.Set(claims.ID, claims)

	return tokenStr, &claims, nil
}

func (s *Service) CheckChallengeToken(tokenString string) (*ChallengeClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ChallengeClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.signingKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*ChallengeClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (s *Service) VerifyResponse(ctx context.Context, ip, challengeToken, challengeResponse string) (*ChallengeClaims, error) {
	claims, err := s.CheckChallengeToken(challengeToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired challenge token: %w", err)
	}

	if !hmac.Equal([]byte(claims.IPHash), []byte(s.ipHashKey(ip))) {
		return nil, fmt.Errorf("challenge IP mismatch")
	}

	if _, ok := s.challengeCache.Get(claims.ID); !ok {
		return nil, fmt.Errorf("challenge already used or expired")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	ok, err := s.provider.Verify(timeoutCtx, challengeResponse, ip)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrFailedChallenge
	}

	s.challengeCache.Delete(claims.ID)

	return claims, nil
}

func (s *Service) NewSession(challenge *ChallengeClaims) *Session {
	return &Session{
		ID:          uuid.NewString(),
		Provider:    s.provider.Name(),
		OriginalURL: challenge.OriginalURL,
		CreatedAt:   s.now(),
		ExpiresAt:   s.now().Add(s.sessionTTL),
		SiteKey:     s.siteKey,
	}
}

// Generate a signed JWT for the session
func (s *Service) CreateSessionToken(session *Session) (string, error) {
	claims := SessionClaims{
		SID: session.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(session.CreatedAt),
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
		},
	}
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to create session token: %w", err)
	}
	return tokenStr, nil
}

// Verify a session JWT and return its claims
func (s *Service) VerifySessionToken(tokenString string) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse session token: %v", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid session token")
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("expired session")
	}

	return claims, nil
}

func (s *Service) WriteSessionCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	if s.cookieDomain != "" {
		cookie.Domain = s.cookieDomain
	}

	http.SetCookie(w, cookie)
}

func (s *Service) ipHashKey(ip string) string {
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) Provider() (name string, siteKey string) {
	return s.provider.Name(), s.siteKey
}

func (s *Service) CookieKey() string {
	return s.cookieName
}
