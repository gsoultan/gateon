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
	"sync"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"golang.org/x/sync/singleflight"
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
		kf, err := sharedJWKSKeyfunc(cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create keyfunc: %w", err)
		}
		v.kf = kf
	}
	return v, nil
}

// jwksKeyfuncs holds one keyfunc per JWKS URL, for the life of the process
// (map[string]keyfunc.Keyfunc).
//
// keyfunc.NewDefault starts a goroutine that refreshes the key set every hour
// and stops only when its context ends -- and NewDefault's is Background, so
// it never does. A validator is built every time a route's chain is: on every
// route, service or middleware change and after every memory-pressure purge,
// and chains have no teardown that could stop one. Building a keyfunc per
// validator therefore left another refresher running on every rebuild, and put
// a synchronous JWKS fetch into every chain build as well.
//
// Validators for the same URL share one instead: a keyfunc is read-only to
// them and safe for concurrent use. The map is bounded by the JWKS URLs an
// operator has configured, not by anything a request can influence.
var (
	jwksKeyfuncs sync.Map
	jwksFlight   singleflight.Group
)

// sharedJWKSKeyfunc returns the keyfunc for url, creating it on first use.
// singleflight makes concurrent first uses of one URL share a single fetch
// without a lock held across it.
func sharedJWKSKeyfunc(url string) (keyfunc.Keyfunc, error) {
	if kf, ok := jwksKeyfuncs.Load(url); ok {
		return kf.(keyfunc.Keyfunc), nil
	}
	v, err, _ := jwksFlight.Do(url, func() (any, error) {
		if kf, ok := jwksKeyfuncs.Load(url); ok {
			return kf, nil
		}
		kf, err := keyfunc.NewDefault([]string{url})
		if err != nil {
			return nil, err
		}
		jwksKeyfuncs.Store(url, kf)
		return kf, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(keyfunc.Keyfunc), nil
}

// Handler returns a middleware that validates JWT tokens. Supports Authorization
// Bearer, query param token, and query param access_token (for WebSocket clients).
func (v *JWTValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsCorsPreflight(r) {
			v.config.stripMappedHeaders(r)
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
			v.config.refuseToken(w, r, next, v.formatJWTError(err))
			return
		}

		if !token.Valid {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
			v.config.refuseToken(w, r, next, errors.New("invalid token"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			v.config.refuseToken(w, r, next, errors.New("invalid token claims"))
			return
		}

		if err := v.validateToken(r.Context(), claims); err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "jwt").Inc()
			telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:jwt").Inc()
			v.config.refuseToken(w, r, next, err)
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
			v.config.stripMappedHeaders(r)
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
			v.config.refuseToken(w, r, next, errors.New("invalid API key"))
			return
		}

		// The key's tenant is the claim it can offer to the route's required
		// scopes and roles and to its claim-to-header mapping.
		if v.config.usesClaims() {
			if err := v.config.authorizeCredential(r, map[string]any{"tenant_id": tenantID}); err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "api_key").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:api_key").Inc()
				v.config.refuseToken(w, r, next, err)
				return
			}
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

// sessionCookieName is the management session cookie's name on a plain-HTTP
// request, and was its name everywhere before ADR 0041.
const sessionCookieName = "gateon_session"

// hostSessionCookieName is its name on a secure request. A browser accepts a
// __Host- cookie only from a secure origin, with Path=/ and no Domain, so
// neither a sibling subdomain nor a plaintext response on the same host can
// plant or overwrite one. A plain-HTTP dashboard cannot have that guarantee:
// the browser refuses the prefix without Secure, so there the name stays.
const hostSessionCookieName = "__Host-" + sessionCookieName

// sessionCookieNameFor names the session cookie for r.
func sessionCookieNameFor(r *http.Request) string {
	if request.IsSecure(r) {
		return hostSessionCookieName
	}
	return sessionCookieName
}

// newSessionCookie builds the session cookie under name. SameSite is Strict:
// the dashboard is a single-page app whose HTML needs no cookie, and every
// call it makes is same-origin, so Strict costs it nothing, while Lax would
// still send the cookie on a top-level navigation another site starts (ADR
// 0041). Neither stops a same-site sender; that is the CSRF guard's job.
//
// Every Set-Cookie for the session goes through here, so the clear always
// carries the attributes the set did: a browser will not clear a Secure cookie
// with a non-Secure Set-Cookie.
func newSessionCookie(r *http.Request, name, token string, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure is conditional by design, not missing. gosec wants
	// a literal true and cannot evaluate request.IsSecure, which is the whole
	// point: the gateway serves both TLS and plain-HTTP entrypoints, and a
	// hardcoded Secure would make the cookie undeliverable on the second
	// without protecting anything on the first. HttpOnly and SameSite are
	// literals because they have no such tradeoff.
	return &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   request.IsSecure(r),
	}
}

// SetSessionCookie sets the HttpOnly, SameSite=Strict session cookie, named
// with the __Host- prefix and Secure when the request is secure.
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
	name := sessionCookieNameFor(r)
	http.SetCookie(w, newSessionCookie(r, name, token, maxAge))
	if name != sessionCookieName {
		// A session from before the rename may still be in the browser under
		// the old name. Expire it, so the next sign-in leaves one session
		// cookie rather than two.
		http.SetCookie(w, newSessionCookie(r, sessionCookieName, "", -1))
	}
}

// ClearSessionCookie instructs the client to clear the session cookie.
// The attributes must match the ones the cookie was set with. A browser matches
// an expiring cookie on name, path and domain, and a Secure cookie cannot be
// cleared by a non-Secure Set-Cookie on an HTTPS origin -- so this has to make
// the same Secure decision as SetSessionCookie, from the same input. On a
// secure request both names are cleared: a session signed in before the
// rename is still under the old one.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	name := sessionCookieNameFor(r)
	http.SetCookie(w, newSessionCookie(r, name, "", -1))
	if name != sessionCookieName {
		http.SetCookie(w, newSessionCookie(r, sessionCookieName, "", -1))
	}
}

// sessionCookieValue returns the session cookie, preferring the __Host- name.
//
// The old name is still read on a secure request, for one release (the one
// after v2.7.0), so that sessions signed in before the upgrade survive it.
// Remove that half in the release after: until then a cookie planted under
// the old name by a sibling subdomain is read when no __Host- cookie is
// present, which is the weakness the prefix exists to close.
func sessionCookieValue(r *http.Request) string {
	if c, err := r.Cookie(hostSessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// ExtractToken returns the token from the session cookie, Authorization
// Bearer, or -- on a WebSocket handshake only -- the query parameters token,
// access_token and auth.
func ExtractToken(r *http.Request) string {
	if t := sessionCookieValue(r); t != "" {
		return t
	}
	if t := bearerToken(r); t != "" {
		return t
	}

	// A token in a query string is written into access logs, browser history
	// and any Referer the page later sends, so it is accepted only where there
	// is no other way to send one: a browser's WebSocket API cannot set a
	// header. Server-sent events used to be included, on nothing more than an
	// Accept header any request can carry; the dashboard's own event stream
	// authenticates with its cookie, and a non-browser SSE client can send
	// Authorization like any other request (ADR 0041).
	if !isWebSocketHandshake(r) {
		return ""
	}
	q := r.URL.Query()
	for _, name := range [...]string{"token", "access_token", "auth"} {
		if t := q.Get(name); t != "" {
			return t
		}
	}
	return ""
}

// isWebSocketHandshake reports whether r is a WebSocket opening handshake as
// RFC 6455 section 4.1 defines one: a GET carrying Upgrade: websocket,
// Connection: Upgrade and a Sec-WebSocket-Key. An Upgrade header alone is not
// one, and a server that upgrades would refuse it.
func isWebSocketHandshake(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		headerHasToken(r.Header, "Upgrade", "websocket") &&
		headerHasToken(r.Header, "Connection", "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

// headerHasToken reports whether any comma-separated element of the named
// header equals token, case-insensitively.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for part := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// StripSessionCookie removes the management session cookie, under either of
// its names, from every Cookie line in h, and drops a line it leaves empty.
// Every other cookie is kept as it was sent.
//
// The proxy calls it on every request, so the common case -- no session
// cookie -- is one substring scan per Cookie line and allocates nothing.
func StripSessionCookie(h http.Header) {
	lines := h["Cookie"]
	kept := lines[:0]
	changed := false
	for _, line := range lines {
		if !strings.Contains(line, sessionCookieName) {
			kept = append(kept, line)
			continue
		}
		rest, removed := withoutSessionCookie(line)
		changed = changed || removed
		if rest != "" {
			kept = append(kept, rest)
		}
	}
	if !changed {
		return
	}
	if len(kept) == 0 {
		delete(h, "Cookie")
		return
	}
	h["Cookie"] = kept
}

// withoutSessionCookie returns line minus any session cookie, and whether it
// had one. A line without one is returned as it was, unallocated.
func withoutSessionCookie(line string) (string, bool) {
	found := false
	for part := range strings.SplitSeq(line, ";") {
		if isSessionCookiePart(part) {
			found = true
			break
		}
	}
	if !found {
		return line, false
	}
	var b strings.Builder
	b.Grow(len(line))
	for part := range strings.SplitSeq(line, ";") {
		part = strings.TrimSpace(part)
		if part == "" || isSessionCookiePart(part) {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(part)
	}
	return b.String(), true
}

// isSessionCookiePart reports whether one name=value pair of a Cookie line is
// the session cookie. The name is matched exactly: a route's OIDC cookie is
// gateon_session_<route>, which is the app's own and must pass.
func isSessionCookiePart(part string) bool {
	name, _, _ := strings.Cut(part, "=")
	name = strings.TrimSpace(name)
	return name == sessionCookieName || name == hostSessionCookieName
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
				cfg.stripMappedHeaders(r)
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
				cfg.refuseToken(w, r, next, errors.New("invalid or expired token"))
				return
			}

			if err := cfg.ValidateClaims(claimsRaw); err != nil {
				telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "paseto").Inc()
				telemetry.RequestFailuresTotal.WithLabelValues(activeRouteID, "auth:paseto").Inc()
				cfg.refuseToken(w, r, next, err)
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

	// An empty username or password is a misconfiguration, not a credential.
	//
	// Without this the middleware authenticates anyone who presents the same
	// empty values -- one header away for an attacker who tries it -- while
	// reading in a config file as "basic auth is enabled". The factory does
	// check, so no shipped configuration reaches here empty; these constructors
	// are exported, and a guarantee that depends on every caller remembering is
	// the kind this project has already been bitten by.
	//
	// Denied at request time rather than refused at construction, which is the
	// same choice PasetoAuth documents a few lines below: these are built once at
	// startup, and returning an error would change an exported signature to
	// prevent a case the caller can already see. A middleware that refuses
	// everything is loud in exactly the way a silent success is not.
	if username == "" || password == "" {
		logger.L.LogError("basic auth configured with an empty username or password; " +
			"refusing every request rather than accepting empty credentials")
		return basicAuthenticator{realm: realm, cfg: cfg, verify: func(string, string) bool { return false }}.middleware
	}
	return basicAuthenticator{realm: realm, cfg: cfg, verify: func(u, p string) bool {
		return subtle.ConstantTimeCompare([]byte(u), []byte(username)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(password)) == 1
	}}.middleware
}

// basicAuthenticator is one configured basic-auth check. The single-user,
// multi-user and refuse-everything variants differ only in how a login is
// verified; they were three copies of one handler, and none of the three
// applied the route's required scopes and roles or its claim-to-header mapping.
type basicAuthenticator struct {
	realm  string
	cfg    AuthBaseConfig
	verify func(user, pass string) bool
}

func (b basicAuthenticator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.serve(next, w, r)
	})
}

func (b basicAuthenticator) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if IsCorsPreflight(r) {
		b.cfg.stripMappedHeaders(r)
		next.ServeHTTP(w, r)
		return
	}
	activeRouteID := GetRouteName(r)

	u, p, ok := r.BasicAuth()
	if !ok || !b.verify(u, p) {
		telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "basic").Inc()
		w.Header().Set("WWW-Authenticate", `Basic realm="`+b.realm+`"`)
		b.cfg.HandleFailure(w, r, next, errors.New("Unauthorized"))
		return
	}
	// The login's username is the claim it can offer to the route's required
	// scopes and roles and to its claim-to-header mapping.
	if b.cfg.usesClaims() {
		if err := b.cfg.authorizeCredential(r, map[string]any{"sub": u}); err != nil {
			telemetry.MiddlewareAuthFailuresTotal.WithLabelValues(activeRouteID, "basic").Inc()
			b.cfg.HandleFailure(w, r, next, err)
			return
		}
	}
	next.ServeHTTP(w, r)
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
	return basicAuthenticator{realm: realm, cfg: cfg, verify: func(u, p string) bool {
		expected, found := pairs[u]
		return found && subtle.ConstantTimeCompare([]byte(p), []byte(expected)) == 1
	}}.middleware, nil
}
