package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gsoultan/gateon/internal/logger"
	"golang.org/x/oauth2"
)

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
			state := generateState()
			// Store state in cookie for verification on callback
			http.SetCookie(w, &http.Cookie{
				Name:     "gateon_state_" + cfg.RouteID,
				Value:    state,
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				MaxAge:   300,
			})

			// Store original URL to redirect back after login
			http.SetCookie(w, &http.Cookie{
				Name:     "gateon_origin_" + cfg.RouteID,
				Value:    r.URL.String(),
				Path:     "/",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				MaxAge:   300,
			})

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

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "gateon_session_" + routeID,
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Expires:  idToken.Expiry,
	})

	// Get origin URL
	origin := "/"
	if originCookie, err := r.Cookie("gateon_origin_" + routeID); err == nil {
		origin = originCookie.Value
	}

	// Cleanup temp cookies
	http.SetCookie(w, &http.Cookie{Name: "gateon_state_" + routeID, MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "gateon_origin_" + routeID, MaxAge: -1, Path: "/"})

	http.Redirect(w, r, origin, http.StatusFound)
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
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
