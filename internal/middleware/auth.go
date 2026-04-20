package middleware

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/telemetry"
)

type contextKey string

const (
	UserContextKey     contextKey = "user"
	TenantIDContextKey contextKey = "tenant_id"
)

// JWTConfig holds configuration for JWT validation.
type JWTConfig struct {
	AuthBaseConfig
	Issuer          string
	Audience        string
	JWKSURL         string          // For remote JWKS validation
	Secret          []byte          // For local secret validation
	RevocationStore RevocationStore // Optional store to check for revoked jti
}

// JWTValidator validates JWT tokens in the Authorization header.
type JWTValidator struct {
	config JWTConfig
	kf     keyfunc.Keyfunc
}

// NewJWTValidator creates a new JWTValidator.
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	v := &JWTValidator{config: cfg}
	if cfg.JWKSURL != "" {
		kf, err := keyfunc.NewDefault([]string{cfg.JWKSURL})
		if err != nil {
			return nil, fmt.Errorf("failed to create keyfunc: %w", err)
		}
		v.kf = kf
	}
	return v, nil
}

// Handler returns a middleware that validates JWT tokens. Supports Authorization
// Bearer, query param token, and query param access_token (for WebSocket clients).
func (v *JWTValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsCorsPreflight(r) {
			next.ServeHTTP(w, r)
			return
		}

		activeRouteID := GetRouteName(r)
		tokenString := ExtractToken(r)

		if tokenString == "" {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			v.config.HandleFailure(w, r, next, errors.New("authorization header, session cookie, or token query param required"))
			return
		}

		token, err := jwt.Parse(tokenString, v.keyFunc)
		if err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			v.config.HandleFailure(w, r, next, v.formatJWTError(err))
			return
		}

		if !token.Valid {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			v.config.HandleFailure(w, r, next, errors.New("invalid token"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			v.config.HandleFailure(w, r, next, errors.New("invalid token claims"))
			return
		}

		if err := v.validateToken(r.Context(), claims); err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			v.config.HandleFailure(w, r, next, err)
			return
		}

		// Success: Inject metadata and continue
		ctx := InjectContext(r.Context(), claims)
		v.config.MapClaimsToHeaders(r, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (v *JWTValidator) keyFunc(token *jwt.Token) (any, error) {
	if v.kf != nil {
		return v.kf.Keyfunc(token)
	}
	// Validate algorithm for HMAC
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return v.config.Secret, nil
}

func (v *JWTValidator) formatJWTError(err error) error {
	if errors.Is(err, jwt.ErrTokenExpired) {
		return errors.New("token expired")
	}
	return fmt.Errorf("invalid token: %v", err)
}

func (v *JWTValidator) validateToken(ctx context.Context, claims jwt.MapClaims) error {
	if v.config.Issuer != "" {
		iss, _ := claims.GetIssuer()
		if iss != v.config.Issuer {
			return errors.New("invalid issuer")
		}
	}

	if v.config.Audience != "" {
		aud, _ := claims.GetAudience()
		if !v.checkAudience(aud) {
			return errors.New("invalid audience")
		}
	}

	// Check revocation
	if v.config.RevocationStore != nil {
		jti, _ := claims["jti"].(string)
		if revoked, _ := v.config.RevocationStore.IsRevoked(ctx, jti); revoked {
			return errors.New("token revoked")
		}
	}

	// RBAC/Scope checks
	return v.config.ValidateClaims(claims)
}

func (v *JWTValidator) checkAudience(aud []string) bool {
	for _, a := range aud {
		if a == v.config.Audience {
			return true
		}
	}
	return false
}

// APIKeyValidator validates API keys.
type APIKeyValidator struct {
	config AuthBaseConfig
	store  APIKeyStore
	header string
	query  string
}

// NewAPIKeyValidator creates a new APIKeyValidator.
func NewAPIKeyValidator(store APIKeyStore, header, query string, baseCfg AuthBaseConfig) *APIKeyValidator {
	if header == "" {
		header = "X-API-Key"
	}
	if query == "" {
		query = "api_key"
	}
	return &APIKeyValidator{
		config: baseCfg,
		store:  store,
		header: header,
		query:  query,
	}
}

// Handler returns a middleware that validates API keys.
func (v *APIKeyValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsCorsPreflight(r) {
			next.ServeHTTP(w, r)
			return
		}
		activeRouteID := GetRouteName(r)

		apiKey := r.Header.Get(v.header)
		if apiKey == "" && v.query != "" && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			apiKey = r.URL.Query().Get(v.query)
		}

		if apiKey == "" {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "api_key").Inc()
			v.config.HandleFailure(w, r, next, errors.New("API key missing"))
			return
		}

		tenantID, ok, err := v.store.GetTenantID(r.Context(), apiKey)
		if err != nil || !ok {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "api_key").Inc()
			v.config.HandleFailure(w, r, next, errors.New("invalid API key"))
			return
		}

		// Set tenant ID in context
		ctx := context.WithValue(r.Context(), TenantIDContextKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenVerifier defines the interface needed to verify tokens.
type TokenVerifier interface {
	VerifyToken(token string) (any, error)
}

const sessionCookieName = "gateon_session"

// SetSessionCookie sets an HttpOnly, SameSite=Lax session cookie. Secure=true when isTLS.
func SetSessionCookie(w http.ResponseWriter, token string, maxAge int, isTLS bool) {
	v := sessionCookieName + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + strconv.Itoa(maxAge)
	if isTLS {
		v += "; Secure"
	}
	w.Header().Add("Set-Cookie", v)
}

// ClearSessionCookie instructs the client to clear the session cookie.
func ClearSessionCookie(w http.ResponseWriter, isTLS bool) {
	v := sessionCookieName + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
	if isTLS {
		v += "; Secure"
	}
	w.Header().Add("Set-Cookie", v)
}

// ExtractToken returns the token from Cookie (gateon_session), Authorization Bearer,
// or query params (token, access_token, auth) for WebSocket clients that cannot set headers.
func ExtractToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if t := bearerToken(r); t != "" {
		return t
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		if t := r.URL.Query().Get("token"); t != "" {
			return t
		}
		if t := r.URL.Query().Get("access_token"); t != "" {
			return t
		}
		if t := r.URL.Query().Get("auth"); t != "" {
			return t
		}
	}
	return ""
}

// bearerToken returns the Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// PasetoAuth returns a middleware that validates PASETO tokens from Authorization Bearer or session cookie.
func PasetoAuth(verifier TokenVerifier, cfg AuthBaseConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			token := ExtractToken(r)
			if token == "" {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				cfg.HandleFailure(w, r, next, errors.New("authorization header, session cookie, or token/access_token/auth query required"))
				return
			}

			claimsRaw, err := verifier.VerifyToken(token)
			if err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				cfg.HandleFailure(w, r, next, errors.New("invalid or expired token"))
				return
			}

			if err := cfg.ValidateClaims(claimsRaw); err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				cfg.HandleFailure(w, r, next, err)
				return
			}

			// Add claims to context and headers
			ctx := InjectContext(r.Context(), claimsRaw)
			cfg.MapClaimsToHeaders(r, claimsRaw)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// BasicAuth returns a middleware that validates Basic Auth credentials (single user).
func BasicAuth(username, password string) Middleware {
	return BasicAuthWithRealm(username, password, "Gateon")
}

// BasicAuthWithRealm returns a middleware with a custom realm.
func BasicAuthWithRealm(username, password, realm string) Middleware {
	return BasicAuthWithConfig(username, password, realm, AuthBaseConfig{})
}

// BasicAuthWithConfig returns a middleware with custom realm and base configuration.
func BasicAuthWithConfig(username, password, realm string, cfg AuthBaseConfig) Middleware {
	if realm == "" {
		realm = "Gateon"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "basic").Inc()
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				cfg.HandleFailure(w, r, next, errors.New("Unauthorized"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BasicAuthUsers validates against multiple users. users is "user1:pass1,user2:pass2".
func BasicAuthUsers(users string, realm string) (Middleware, error) {
	return BasicAuthUsersWithConfig(users, realm, AuthBaseConfig{})
}

// BasicAuthUsersWithConfig validates against multiple users with base configuration.
func BasicAuthUsersWithConfig(users string, realm string, cfg AuthBaseConfig) (Middleware, error) {
	if users == "" {
		return nil, fmt.Errorf("basic auth requires users (format: user1:pass1,user2:pass2)")
	}
	if realm == "" {
		realm = "Gateon"
	}
	pairs := make(map[string]string)
	for _, part := range strings.Split(users, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid user format: %q (expected user:password)", part)
		}
		u, p := part[:idx], part[idx+1:]
		pairs[u] = p
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("basic auth requires at least one user")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			u, p, ok := r.BasicAuth()
			if !ok {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "basic").Inc()
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				cfg.HandleFailure(w, r, next, errors.New("Unauthorized"))
				return
			}
			expected, found := pairs[u]
			if !found || subtle.ConstantTimeCompare([]byte(p), []byte(expected)) != 1 {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "basic").Inc()
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				cfg.HandleFailure(w, r, next, errors.New("Unauthorized"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
