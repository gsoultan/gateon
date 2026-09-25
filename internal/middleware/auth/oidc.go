// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

// oidcTempCookieTTL bounds the state and origin cookies. They exist only for
// the round trip to the provider; anything longer widens the window in which a
// stolen state value is still accepted.
const oidcTempCookieTTL = 300

const (
	// defaultOIDCProviderTimeout bounds every call the relying party makes to
	// the provider: discovery, the token exchange and key-set fetches. Left to
	// the library they run on http.DefaultClient, which never gives up.
	defaultOIDCProviderTimeout = 10 * time.Second
	// defaultOIDCDiscoveryRetry is the least time between discovery attempts
	// while the provider is failing, so a burst of traffic to a route whose
	// provider is down does not become a burst of requests against it.
	defaultOIDCDiscoveryRetry = 5 * time.Second
)

type OIDCProxyConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	RouteID      string
	// DiscoveryTimeout bounds each call to the provider. Zero means
	// defaultOIDCProviderTimeout.
	DiscoveryTimeout time.Duration
	// DiscoveryRetryInterval is the least time between discovery attempts
	// after one fails. Zero means defaultOIDCDiscoveryRetry.
	DiscoveryRetryInterval time.Duration
}

// OIDCProxy protects a route with the OpenID Connect authorization-code flow.
//
// Provider discovery happens on first use, not here. Construction runs while
// the proxy cache builds a route's chain, and discovery used to run here on
// http.DefaultClient: a provider that accepted the connection and never
// answered held the build open for as long as it hung, and a provider that was
// merely down made the build fail, so the route refused traffic until someone
// edited it — the failure was cached with the chain. The middleware now builds
// without touching the network and resolves the provider when a request needs
// it: the route refuses with 503 while the provider is unreachable and recovers
// by itself once it is back.
func OIDCProxy(cfg OIDCProxyConfig) (Middleware, error) {
	rp, err := newOIDCRelyingParty(cfg)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rp.serve(next, w, r)
		})
	}, nil
}

// oidcRelyingParty is one route's oidc middleware: its configuration, the
// cookies it owns, and the provider's endpoints once discovery has succeeded.
type oidcRelyingParty struct {
	cfg           OIDCProxyConfig
	callbackPath  string
	scopes        []string
	client        *http.Client
	stateCookie   string
	originCookie  string
	sessionCookie string

	resolved atomic.Pointer[oidcEndpoints]
	flight   singleflight.Group
	mu       sync.Mutex // guards lastErr and retryAt
	lastErr  error
	retryAt  time.Time
}

// oidcEndpoints is what a successful discovery yields.
type oidcEndpoints struct {
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDCRelyingParty(cfg OIDCProxyConfig) (*oidcRelyingParty, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("oidc requires an issuer URL")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("oidc requires a client_id")
	}
	callbackPath, err := oidcCallbackPath(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}
	if cfg.DiscoveryTimeout <= 0 {
		cfg.DiscoveryTimeout = defaultOIDCProviderTimeout
	}
	if cfg.DiscoveryRetryInterval <= 0 {
		cfg.DiscoveryRetryInterval = defaultOIDCDiscoveryRetry
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}
	key := oidcCookieKey(cfg.RouteID)
	return &oidcRelyingParty{
		cfg:           cfg,
		callbackPath:  callbackPath,
		scopes:        scopes,
		client:        &http.Client{Timeout: cfg.DiscoveryTimeout},
		stateCookie:   "gateon_state_" + key,
		originCookie:  "gateon_origin_" + key,
		sessionCookie: "gateon_session_" + key,
	}, nil
}

// oidcCallbackPath is the path of the redirect URL, which is how the
// middleware recognises the provider sending the user back. It has to be an
// absolute http(s) URL — that is what the provider is sent as redirect_uri and
// the only shape a provider accepts — and its query is not part of the path.
func oidcCallbackPath(redirectURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(redirectURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("oidc requires redirect_url to be an absolute http(s) URL, got %q", redirectURL)
	}
	if u.Path == "" {
		return "/", nil
	}
	return u.Path, nil
}

// oidcCookieKey turns the route label into a cookie-name suffix. The label is
// the route's display name when it has one, and a name such as "My App" is not
// a valid cookie-name token: net/http drops such a cookie without an error, so
// the login would silently loop. Hashing keeps any label valid and keeps two
// routes' cookies apart.
func oidcCookieKey(routeID string) string {
	if routeID == "" {
		return "global"
	}
	sum := sha256.Sum256([]byte(routeID))
	return hex.EncodeToString(sum[:6])
}

func (rp *oidcRelyingParty) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	// Strip any client-supplied identity headers up front: only a
	// successfully verified session may set them (below). Otherwise a
	// client could inject X-Forwarded-User and have it forwarded when
	// claim extraction fails but the request still reaches the backend.
	r.Header.Del("X-Forwarded-User")
	r.Header.Del("X-Forwarded-Email")
	r.Header.Del("X-Forwarded-Name")

	ep, err := rp.endpoints(r.Context())
	if err != nil {
		// Fail closed: without the provider nothing can be verified, and a
		// route configured with authentication must not serve without it.
		http.Error(w, "Service Unavailable: identity provider unreachable", http.StatusServiceUnavailable)
		return
	}

	if r.URL.Path == rp.callbackPath {
		rp.handleCallback(w, r, ep)
		return
	}
	if rp.forwardSession(r, ep) {
		next.ServeHTTP(w, r)
		return
	}
	rp.startLogin(w, r, ep)
}

// endpoints returns the provider's endpoints, discovering them on first use.
// Concurrent requests share one discovery, and a request whose client goes away
// stops waiting for it without cancelling it for the others.
func (rp *oidcRelyingParty) endpoints(ctx context.Context) (*oidcEndpoints, error) {
	if ep := rp.resolved.Load(); ep != nil {
		return ep, nil
	}
	// The discovery is shared by every request waiting on it, so it must not
	// inherit any one caller's context: a client that disconnects would cancel
	// it for all the others. It carries its own timeout instead.
	//nolint:contextcheck // deliberately detached from the request; bounded by DiscoveryTimeout.
	ch := rp.flight.DoChan("discover", func() (any, error) { return rp.discover() })
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		ep, _ := res.Val.(*oidcEndpoints)
		return ep, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// discover fetches the provider's discovery document. A failure is remembered
// for DiscoveryRetryInterval and returned to every request in that window
// without asking the provider again.
func (rp *oidcRelyingParty) discover() (*oidcEndpoints, error) {
	if ep := rp.resolved.Load(); ep != nil {
		return ep, nil
	}
	rp.mu.Lock()
	if time.Now().Before(rp.retryAt) {
		err := rp.lastErr
		rp.mu.Unlock()
		return nil, err
	}
	rp.mu.Unlock()

	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), rp.client), rp.cfg.DiscoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, rp.cfg.Issuer)
	if err != nil {
		err = fmt.Errorf("oidc discovery for %s: %w", rp.cfg.Issuer, err)
		logger.L.LogError("oidc: provider discovery failed; the route refuses requests until it succeeds",
			"route", rp.cfg.RouteID, "issuer", rp.cfg.Issuer, "error", err,
			"retry_after", rp.cfg.DiscoveryRetryInterval)
		rp.mu.Lock()
		rp.lastErr, rp.retryAt = err, time.Now().Add(rp.cfg.DiscoveryRetryInterval)
		rp.mu.Unlock()
		return nil, err
	}
	// The provider keeps the client from ctx, not ctx itself, so the key-set
	// fetches the verifier makes later are bounded by the same client timeout
	// and are not cancelled when this function's deadline passes.
	ep := &oidcEndpoints{
		oauth2: oauth2.Config{
			ClientID:     rp.cfg.ClientID,
			ClientSecret: rp.cfg.ClientSecret,
			RedirectURL:  rp.cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       rp.scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: rp.cfg.ClientID}),
	}
	rp.resolved.Store(ep)
	return ep, nil
}

// forwardSession verifies the session cookie and, when it holds a valid ID
// token, forwards the caller's identity to the backend.
func (rp *oidcRelyingParty) forwardSession(r *http.Request, ep *oidcEndpoints) bool {
	sessionCookie, err := r.Cookie(rp.sessionCookie)
	if err != nil || sessionCookie.Value == "" {
		return false
	}
	token, err := ep.verifier.Verify(r.Context(), sessionCookie.Value)
	if err != nil {
		return false
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Sub   string `json:"sub"`
	}
	if err := token.Claims(&claims); err == nil {
		r.Header.Set("X-Forwarded-User", claims.Sub)
		r.Header.Set("X-Forwarded-Email", claims.Email)
		r.Header.Set("X-Forwarded-Name", claims.Name)
	}
	return true
}

// startLogin sends an unauthenticated caller to the provider, remembering the
// state to check on the way back and the page to return them to.
func (rp *oidcRelyingParty) startLogin(w http.ResponseWriter, r *http.Request, ep *oidcEndpoints) {
	state, err := generateState()
	if err != nil {
		logger.L.LogError("oidc: failed to generate state", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	// State cookie for CSRF verification on callback, and the origin to return
	// the user to. Both are short-lived and both are cleared by the callback
	// once used. The origin is base64url-encoded because a cookie value cannot
	// carry ';', '"' or '\', and net/http drops them silently, which returned
	// the user to a different URL than the one they asked for.
	origin := base64.RawURLEncoding.EncodeToString([]byte(r.URL.RequestURI()))
	http.SetCookie(w, newOIDCCookie(r, rp.stateCookie, state, oidcTempCookieTTL))
	http.SetCookie(w, newOIDCCookie(r, rp.originCookie, origin, oidcTempCookieTTL))

	// #nosec G710 -- the destination is the provider authorize URL built by
	// oauth2Config from the operator-configured issuer, not from request
	// input. (Was annotated G307, a rule that never applied here.)
	http.Redirect(w, r, ep.oauth2.AuthCodeURL(state), http.StatusFound)
}

// handleCallback completes the flow when the provider sends the user back.
// It reads the cookies this same middleware set, by name, rather than deriving
// a route from the callback path: the derivation and the names never agreed,
// so the state check failed on every login.
func (rp *oidcRelyingParty) handleCallback(w http.ResponseWriter, r *http.Request, ep *oidcEndpoints) {
	stateCookie, err := r.Cookie(rp.stateCookie)
	want := r.URL.Query().Get("state")
	// An empty state never matches: the middleware only issues non-empty ones,
	// and equal empties would let a planted empty cookie satisfy the check.
	if err != nil || stateCookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(want)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	ctx := oidc.ClientContext(r.Context(), rp.client)
	oauth2Token, err := ep.oauth2.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		logger.L.LogError("oidc: failed to exchange token", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}
	idToken, err := ep.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID Token verification failed", http.StatusInternalServerError)
		return
	}

	// Session cookie. It carries the raw ID token, so it gets the same treatment
	// as the management-plane session cookie (SetSessionCookie in auth.go).
	// MaxAge is derived from the token's own expiry so the cookie cannot outlive
	// the credential inside it.
	maxAge := max(int(time.Until(idToken.Expiry).Seconds()), 0)
	http.SetCookie(w, newOIDCCookie(r, rp.sessionCookie, rawIDToken, maxAge))

	origin := rp.returnPath(r)

	// Cleanup temp cookies. The attributes have to match the ones they were set
	// with — a browser matches an expiring cookie on name, path and domain, and
	// a Secure cookie cannot be cleared by a non-Secure Set-Cookie on an HTTPS
	// origin. Sending a bare deletion would leave the state cookie live for its
	// full 300s instead of ending it at first use.
	expireOIDCCookie(w, r, rp.stateCookie)
	expireOIDCCookie(w, r, rp.originCookie)

	// #nosec G710 -- not an open redirect: origin is either the "/" default or a
	// cookie value that passed sameOriginPath, which requires a leading "/" and
	// rejects the scheme-relative "//host" and "/\host" forms. An absolute URL
	// never reaches here.
	http.Redirect(w, r, origin, http.StatusFound)
}

// returnPath is the page the user asked for before logging in, if the origin
// cookie still holds one that stays on this site, and "/" otherwise.
func (rp *oidcRelyingParty) returnPath(r *http.Request) string {
	c, err := r.Cookie(rp.originCookie)
	if err != nil {
		return "/"
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || !sameOriginPath(string(raw)) {
		return "/"
	}
	return string(raw)
}

// sameOriginPath accepts only a path on this site. Browsers treat a backslash
// after the leading slash as a second slash, so "/\evil.com" is as much a
// scheme-relative URL as "//evil.com" and is refused with it.
func sameOriginPath(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.HasPrefix(v, `/\`)
}

// newOIDCCookie builds every cookie this middleware issues, so the security
// attributes are decided in one place instead of being retyped at each call
// site — which is how three of the four came to differ from the hardened
// management-plane cookie in SetSessionCookie.
//
// Secure comes from request.IsSecure, not r.TLS. r.TLS answers "did this
// process terminate the TLS", which is the wrong question: behind a load
// balancer, ingress or CDN it is nil on a request the user made over HTTPS, and
// keying Secure off it drops the attribute in exactly those deployments, so the
// session cookie then rides the next plaintext request to the same host.
//
// SameSite is Lax, not Strict: the provider returns the user through a
// top-level cross-site redirect and Strict withholds the cookie on that
// navigation, so the callback would never see the state it must compare
// against. Lax is the strongest mode this flow tolerates. Unset is not a
// synonym — the attribute is then omitted and the posture becomes whatever the
// browser defaults to.
func newOIDCCookie(r *http.Request, name, value string, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure is set from the resolved request scheme two lines
	// down. gosec requires a literal true and cannot follow the variable, so it
	// reports the attribute as absent when it is conditional by design.
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   request.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// expireOIDCCookie clears a temporary OIDC cookie. The attributes must mirror
// the ones it was set with: a browser matches on name, path and domain, and a
// Secure cookie cannot be cleared by a non-Secure Set-Cookie on an HTTPS
// origin, so a bare deletion would leave the state cookie live for its full TTL
// instead of ending it at first use.
func expireOIDCCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, newOIDCCookie(r, name, "", -1))
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// --- Resource-server mode -------------------------------------------------
//
// Everything above implements the relying-party half of OIDC: the redirect to
// the provider, the callback, and the cookies that survive the round trip.
// What follows is the other half, where the gateway is handed a token someone
// else issued and only has to verify it. They share a provider, a discovery
// document and a set of failure modes, which is why they share a file.

// oidcDiscoveryResponse represents the OpenID Connect Discovery document.
type oidcDiscoveryResponse struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

const oidcDiscoveryTimeout = 15 * time.Second

// NewOIDCValidator creates a JWT validator by fetching OIDC discovery from the issuer.
// Config: issuer (required), audience (optional), baseCfg.
func NewOIDCValidator(issuer, audience string, baseCfg AuthBaseConfig) (*JWTValidator, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("oidc auth requires issuer URL")
	}
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: oidcDiscoveryTimeout}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery returned %d", resp.StatusCode)
	}

	var disc oidcDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("oidc discovery invalid JSON: %w", err)
	}
	if disc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery missing jwks_uri")
	}

	// Compared exactly, as discovery states it: a token's iss must match the
	// issuer string character for character (OpenID Connect Core 3.1.3.7).
	// Trimming a trailing slash here refused every token from providers whose
	// issuer ends in one, Auth0 among them.
	effectiveIssuer := disc.Issuer
	if effectiveIssuer == "" {
		effectiveIssuer = issuer
	}

	jwtCfg := JWTConfig{
		AuthBaseConfig: baseCfg,
		Issuer:         effectiveIssuer,
		Audience:       strings.TrimSpace(audience),
		JWKSURL:        disc.JWKSURI,
	}
	return NewJWTValidator(jwtCfg)
}
