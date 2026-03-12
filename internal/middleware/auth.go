package middleware

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
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

// APIKeyValidator validates API keys.
type APIKeyValidator struct {
	Keys map[string]string // Key -> TenantID mapping (simplified)
}

// NewAPIKeyValidator creates a new APIKeyValidator.
func NewAPIKeyValidator(keys map[string]string) *APIKeyValidator {
	return &APIKeyValidator{Keys: keys}
}

// Handler returns a middleware that validates API keys.
func (v *APIKeyValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
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

// PasetoAuth returns a middleware that validates PASETO tokens in the Authorization header.
func PasetoAuth(verifier TokenVerifier) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Authorization header required", "")
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Invalid authorization format", "")
				return
			}

			claims, err := verifier.VerifyToken(parts[1])
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

// BasicAuth returns a middleware that validates Basic Auth credentials.
func BasicAuth(username, password string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Gateon UI"`)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
