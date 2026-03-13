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
	"github.com/gateon/gateon/internal/httputil"
)

type contextKey string

const (
	UserContextKey     contextKey = "user"
	TenantIDContextKey contextKey = "tenant_id"
)

// JWTConfig holds configuration for JWT validation.
type JWTConfig struct {
	Issuer   string
	Audience string
	JWKSURL  string // For remote JWKS validation
	Secret   []byte // For local secret validation
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

// Handler returns a middleware that validates JWT tokens.
func (v *JWTValidator) Handler(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "authorization header missing", "")
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid authorization header format", "")
				return
			}

			tokenString := parts[1]
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if v.kf != nil {
				return v.kf.Keyfunc(token)
			}
			// Validate algorithm for HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return v.config.Secret, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "token expired", "")
				return
			}
			httputil.WriteJSONError(w, http.StatusUnauthorized, fmt.Sprintf("invalid token: %v", err), "")
			return
		}

		if !token.Valid {
			httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid token", "")
			return
		}

		// Verify claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid token claims", "")
			return
		}

		if v.config.Issuer != "" {
			iss, _ := claims.GetIssuer()
			if iss != v.config.Issuer {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid issuer", "")
				return
			}
		}

		if v.config.Audience != "" {
			aud, _ := claims.GetAudience()
			found := false
			for _, a := range aud {
				if a == v.config.Audience {
					found = true
					break
				}
			}
			if !found {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid audience", "")
				return
			}
		}

		// Set claims in context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)

		// Try to extract tenant_id from claims
		if tenantID, ok := claims["tenant_id"].(string); ok {
			ctx = context.WithValue(ctx, TenantIDContextKey, tenantID)
		} else if sub, ok := claims["sub"].(string); ok {
			// Fallback to sub as tenant_id if not present
			ctx = context.WithValue(ctx, TenantIDContextKey, sub)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// APIKeyValidator validates API keys from a configurable header.
type APIKeyValidator struct {
	Keys       map[string]string // Key -> TenantID mapping
	HeaderName string            // e.g. "X-API-Key"
}

// NewAPIKeyValidator creates a new APIKeyValidator. headerName defaults to "X-API-Key".
func NewAPIKeyValidator(keys map[string]string, headerName string) *APIKeyValidator {
	if headerName == "" {
		headerName = "X-API-Key"
	}
	return &APIKeyValidator{Keys: keys, HeaderName: headerName}
}

// Handler returns a middleware that validates API keys.
func (v *APIKeyValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get(v.HeaderName)
		if apiKey == "" {
			httputil.WriteJSONError(w, http.StatusUnauthorized, "API key missing", "")
			return
		}

		tenantID, ok := v.Keys[apiKey]
		if !ok {
			httputil.WriteJSONError(w, http.StatusUnauthorized, "invalid API key", "")
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

// extractToken returns the token from Cookie (gateon_session) or Authorization Bearer.
func extractToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
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
func PasetoAuth(verifier TokenVerifier) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Authorization header or session cookie required", "")
				return
			}

			claims, err := verifier.VerifyToken(token)
			if err != nil {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Invalid or expired token", "")
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
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
	if realm == "" {
		realm = "Gateon"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BasicAuthUsers validates against multiple users. users is "user1:pass1,user2:pass2".
func BasicAuthUsers(users string, realm string) (Middleware, error) {
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
			u, p, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
				return
			}
			expected, found := pairs[u]
			if !found || subtle.ConstantTimeCompare([]byte(p), []byte(expected)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
