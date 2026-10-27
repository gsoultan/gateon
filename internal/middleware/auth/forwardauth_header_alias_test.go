// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A backend that folds header-name separators (PHP/CGI, WSGI, nginx with
// underscores_in_headers on) reads X-Auth-User, X_Auth_User and X.Auth.User as
// one variable. ForwardAuth deletes only the canonical spelling of its
// auth_response_headers, so before this fix a client-supplied X_Auth_User alias
// survived to the backend carrying the gateway's identity guarantee -- the
// Traefik ForwardAuth spoof, CVE-2026-88879 / CVE-2026-88011.
func TestForwardAuthStripsIdentityHeaderAliasesToTheBackend(t *testing.T) {
	addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Auth-User", "alice")
		w.WriteHeader(http.StatusOK)
	})
	cfg := ForwardAuthConfig{Address: addr, AuthResponseHeaders: []string{"X-Auth-User"}}

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X_Auth_User", "attacker")
	req.Header.Set("X.Auth.User", "attacker")

	rr, seen := runForwardAuth(t, cfg, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if got := seen.Get("X-Auth-User"); got != "alice" {
		t.Errorf("X-Auth-User = %q, want the auth service's %q", got, "alice")
	}
	for _, alias := range []string{"X_Auth_User", "X.Auth.User"} {
		if vals := seen.Values(alias); len(vals) != 0 {
			t.Errorf("backend saw identity alias %s = %q; it folds to X-Auth-User "+
				"and must be stripped", alias, vals)
		}
	}
}

// The X-Forwarded-* values the auth service reasons about are the gateway's to
// set. An alias form of one reaches the auth service through the header copy
// and, if the auth service folds separators, is read as the trusted value --
// the pre-auth-decision bypass, CVE-2026-39858.
func TestForwardAuthStripsForwardedHeaderAliasesToTheAuthService(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X_Forwarded_Proto", "https")
	req.Header.Set("X.Forwarded.Host", "trusted.internal")

	seen := forwardedHeadersSeen(t, ForwardAuthConfig{}, req)

	for _, alias := range []string{"X_Forwarded_Proto", "X.Forwarded.Host"} {
		if vals := seen.Values(alias); len(vals) != 0 {
			t.Errorf("auth service saw forwarded alias %s = %q; it folds to a "+
				"gateway-set X-Forwarded-* header and must be stripped", alias, vals)
		}
	}
	// The canonical values the gateway sets must still be the real ones.
	if got := seen.Get("X-Forwarded-Host"); got != "api.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want the gateway's %q", got, "api.example.com")
	}
	if got := seen.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want the gateway's %q", got, "http")
	}
}
