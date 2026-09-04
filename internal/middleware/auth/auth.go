// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
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
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
			v.config.HandleFailure(w, r, next, errors.New("authorization header, session cookie, or token query param required"))
			return
		}

		token, err := jwt.Parse(tokenString, v.keyFunc, jwt.WithValidMethods(v.validMethods()))
		if err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
			v.config.HandleFailure(w, r, next, v.formatJWTError(err))
			return
		}

		if !token.Valid {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
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
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
			v.config.HandleFailure(w, r, next, err)
			return
		}

		// Zero Trust Check
		userID := fmt.Sprintf("%v", claims["sub"])
		clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
		fp := telemetry.GenerateFingerprint(r)
		if err := telemetry.CheckZeroTrust(userID, fp.Hash, clientIP, r); err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "zerotrust").Inc()
			http.Error(w, "Security check failed: "+err.Error(), http.StatusForbidden)
			return
		}

		// Success: Inject metadata and continue
		ctx := InjectContext(r.Context(), claims)
		v.config.MapClaimsToHeaders(r, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validMethods returns the JWT signing algorithms this validator will accept.
// Enforcing an explicit allowlist (defense-in-depth) blocks "alg=none" and
// HS/RS algorithm-confusion attacks in our own code rather than relying on
// library internals. JWKS-backed validators expect asymmetric algorithms;
// the local-secret path expects HMAC.
func (v *JWTValidator) validMethods() []string {
	if v.kf != nil {
		return []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
	}
	return []string{"HS256", "HS384", "HS512"}
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
	return fmt.Errorf("invalid token: %w", err)
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

	// Check revocation.
	//
	// The error is deliberately fatal to the request rather than discarded.
	// RedisRevocationStore returns (false, err) when the backend is unreachable,
	// so treating a failed lookup as "not revoked" honoured every revoked token
	// for as long as Redis was down — a restart, a network blip, a timeout or a
	// wrong password. Revocation is the control you reach for after a
	// compromise, which makes an outage precisely the wrong moment to stop
	// enforcing it, and the operator turned this on deliberately.
	//
	// The cause goes to the log, not to the caller: HandleFailure writes
	// err.Error() straight into the response body, so a wrapped driver error
	// would hand an unauthenticated client the address of an internal service.
	if v.config.RevocationStore != nil {
		jti, _ := claims["jti"].(string)
		revoked, err := v.config.RevocationStore.IsRevoked(ctx, jti)
		if err != nil {
			logger.L.LogError("auth: revocation lookup failed, denying request", "error", err)
			return errors.New("token revocation status unavailable")
		}
		if revoked {
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
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:api_key").Inc()
			v.config.HandleFailure(w, r, next, errors.New("API key missing"))
			return
		}

		tenantID, ok, err := v.store.GetTenantID(r.Context(), apiKey)
		if err != nil || !ok {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "api_key").Inc()
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:api_key").Inc()
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
// It takes the request rather than a bool because the bool was being computed
// wrongly at all three call sites, as `r.TLS != nil`. That answers "did this
// process terminate the TLS", which is the wrong question: behind a load
// balancer, ingress or CDN it is nil on a request the user made over HTTPS, so
// the management session cookie lost its Secure attribute in exactly the
// deployments that terminate TLS elsewhere -- and then rode the next plaintext
// request to the same host. request.IsSecure asks whether the request reached
// the edge over TLS, and only trusts X-Forwarded-Proto from a trusted peer.
//
// The same reasoning that put newOIDCCookie in one place applies here: an
// attribute every caller has to recompute is an attribute some caller will get
// wrong.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	// #nosec G124 -- Secure is conditional by design, not missing. gosec wants
	// a literal true and cannot evaluate request.IsSecure, which is the whole
	// point: the gateway serves both TLS and plain-HTTP entrypoints, and a
	// hardcoded Secure would make the cookie undeliverable on the second
	// without protecting anything on the first. HttpOnly and SameSite are
	// literals here precisely because they have no such tradeoff. Building the
	// header by hand hid this from gosec entirely; being visible and explained
	// is the better state.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   request.IsSecure(r),
	})
}

// ClearSessionCookie instructs the client to clear the session cookie.
// The attributes must match the ones the cookie was set with. A browser matches
// an expiring cookie on name, path and domain, and a Secure cookie cannot be
// cleared by a non-Secure Set-Cookie on an HTTPS origin -- so this has to make
// the same Secure decision as SetSessionCookie, from the same input.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- same as SetSessionCookie, and it must stay the same: a
	// browser will not clear a Secure cookie with a non-Secure Set-Cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   request.IsSecure(r),
	})
}

// ExtractToken returns the token from Cookie (gateon_session), Authorization Bearer,
// or query params (token, access_token, auth) to support WebSocket, SSE, and CLI clients.
func ExtractToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if t := bearerToken(r); t != "" {
		return t
	}

	// Query parameters are only accepted for WebSocket/SSE to prevent token leakage in browser history
	// for standard web requests, while still allowing auth for protocols that don't support headers well.
	if !isWebSocketOrSSE(r) {
		return ""
	}

	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	if t := r.URL.Query().Get("access_token"); t != "" {
		return t
	}
	if t := r.URL.Query().Get("auth"); t != "" {
		return t
	}
	return ""
}

func isWebSocketOrSSE(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		return true
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/event-stream") {
		return true
	}
	return false
}

// bearerToken returns the Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "bearer ") {
		return ""
	}
	return authHeader[7:]
}

// PasetoAuth returns a middleware that validates PASETO tokens from Authorization Bearer or session cookie.
//
// A nil verifier is tolerated and denies every request. Callers build this
// middleware once at startup, when the verifier may not exist yet, so refusing
// to construct it would force them to decide at construction time whether
// authentication will ever be possible — and a caller that guesses wrong there
// either serves unauthenticated or never recovers. Denying at request time
// keeps that decision where the information is.
func PasetoAuth(verifier TokenVerifier, cfg AuthBaseConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			if verifier == nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:paseto").Inc()
				cfg.HandleFailure(w, r, next, errors.New("no token verifier is configured"))
				return
			}

			token := ExtractToken(r)
			if token == "" {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:paseto").Inc()
				cfg.HandleFailure(w, r, next, errors.New("authorization header, session cookie, or token/access_token/auth query required"))
				return
			}

			claimsRaw, err := verifier.VerifyToken(token)
			if err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:paseto").Inc()
				cfg.HandleFailure(w, r, next, errors.New("invalid or expired token"))
				return
			}

			if err := cfg.ValidateClaims(claimsRaw); err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:paseto").Inc()
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
