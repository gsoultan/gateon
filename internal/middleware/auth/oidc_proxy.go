// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"golang.org/x/oauth2"
)

// oidcTempCookieTTL bounds the state and origin cookies. They exist only for
// the round trip to the provider; anything longer widens the window in which a
// stolen state value is still accepted.
const oidcTempCookieTTL = 300

type OIDCProxyConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	RouteID      string
}

func OIDCProxy(cfg OIDCProxyConfig) (Middleware, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip any client-supplied identity headers up front: only a
			// successfully verified session may set them (below). Otherwise a
			// client could inject X-Forwarded-User and have it forwarded when
			// claim extraction fails but the request still reaches the backend.
			r.Header.Del("X-Forwarded-User")
			r.Header.Del("X-Forwarded-Email")
			r.Header.Del("X-Forwarded-Name")

			// 1. Check if it's the callback
			callbackPath := parsePath(cfg.RedirectURL)
			if r.URL.Path == callbackPath {
				handleOIDCCallback(w, r, oauth2Config, verifier)
				return
			}

			// 2. Check for session cookie
			sessionCookie, err := r.Cookie("gateon_session_" + cfg.RouteID)
			if err == nil && sessionCookie.Value != "" {
				// Validate ID token from cookie
				token, err := verifier.Verify(r.Context(), sessionCookie.Value)
				if err == nil {
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
					next.ServeHTTP(w, r)
					return
				}
			}

			// 3. Not authenticated, redirect to provider
			state, err := generateState()
			if err != nil {
				logger.L.LogError("oidc: failed to generate state", "error", err)
				http.Error(w, "Authentication failed", http.StatusInternalServerError)
				return
			}
			// State cookie for CSRF verification on callback, and the origin to
			// return the user to. Both are short-lived and both are cleared by
			// the callback once used.
			http.SetCookie(w, newOIDCCookie(r, "gateon_state_"+cfg.RouteID, state, oidcTempCookieTTL))
			http.SetCookie(w, newOIDCCookie(r, "gateon_origin_"+cfg.RouteID, r.URL.String(), oidcTempCookieTTL))

			// #nosec G710 -- the destination is the provider authorize URL built by
			// oauth2Config from the operator-configured issuer, not from request
			// input. (Was annotated G307, a rule that never applied here.)
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
		})
	}, nil
}

func handleOIDCCallback(w http.ResponseWriter, r *http.Request, oauth2Config oauth2.Config, verifier *oidc.IDTokenVerifier) {
	routeID := strings.TrimPrefix(r.URL.Path, "/_gateon/oidc/callback/")
	if routeID == r.URL.Path { // Fallback if not nested
		routeID = "global"
	}

	stateCookie, err := r.Cookie("gateon_state_" + routeID)
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	oauth2Token, err := oauth2Config.Exchange(r.Context(), code)
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

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "ID Token verification failed", http.StatusInternalServerError)
		return
	}

	// Session cookie. It carries the raw ID token, so it gets the same treatment
	// as the management-plane session cookie (SetSessionCookie in auth.go).
	// MaxAge is derived from the token's own expiry so the cookie cannot outlive
	// the credential inside it.
	maxAge := int(time.Until(idToken.Expiry).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(w, newOIDCCookie(r, "gateon_session_"+routeID, rawIDToken, maxAge))

	// Get origin URL. Only accept a same-origin relative path to prevent an
	// open redirect (reject absolute URLs and scheme-relative "//host" values).
	origin := "/"
	if originCookie, err := r.Cookie("gateon_origin_" + routeID); err == nil {
		if v := originCookie.Value; strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") {
			origin = v
		}
	}

	// Cleanup temp cookies. The attributes have to match the ones they were set
	// with — a browser matches an expiring cookie on name, path and domain, and
	// a Secure cookie cannot be cleared by a non-Secure Set-Cookie on an HTTPS
	// origin. Sending a bare deletion would leave the state cookie live for its
	// full 300s instead of ending it at first use.
	expireOIDCCookie(w, r, "gateon_state_"+routeID)
	expireOIDCCookie(w, r, "gateon_origin_"+routeID)

	// #nosec G710 -- not an open redirect: origin is either the "/" default or a
	// cookie value that passed the same-origin check above, which requires a
	// leading "/" and rejects scheme-relative "//host". An absolute URL never
	// reaches here.
	http.Redirect(w, r, origin, http.StatusFound)
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

func parsePath(rawURL string) string {
	if strings.HasPrefix(rawURL, "http") {
		// Extract path from URL
		if parts := strings.SplitN(rawURL, "/", 4); len(parts) >= 4 {
			return "/" + parts[3]
		}
		return "/"
	}
	return rawURL
}
