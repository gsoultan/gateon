// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security"
	wafmw "github.com/gsoultan/gateon/internal/middleware/security/waf"
	"github.com/gsoultan/gateon/internal/request"
)

// routeChain is a route as the router assembles it: mws, then the service
// boundary, then the backend.
func routeChain(backend http.Handler, mws ...kind.Middleware) http.Handler {
	return kind.Chain(append(mws, request.ServiceBoundary)...)(backend)
}

// TestOnlyAuthenticationsRefusalsAreCredentialAttempts is ADR 0059: the
// brute-force check counted every POST answered 401 or 403 as a refused
// login, those that never reached a credential check included. A user whose
// form posts the WAF refused, or a scanner's POSTs to a trap path, were
// counted as guessing passwords and shunned for it. A backend's refusal --
// its login form -- and the gateway's own authentication still count.
func TestOnlyAuthenticationsRefusalsAreCredentialAttempts(t *testing.T) {
	waf, err := wafmw.NewWAF(map[string]string{"route_id": "refusal-origin"}, security.Deps{})
	if err != nil {
		t.Fatalf("build WAF: %v", err)
	}
	trap := security.Deception(security.DeceptionConfig{RouteID: "refusal-origin", HoneypotPaths: []string{"/wp-login.php"}})
	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(authService.Close)
	forward, err := ForwardAuth(ForwardAuthConfig{Address: authService.URL})
	if err != nil {
		t.Fatalf("build forward auth: %v", err)
	}
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for _, tc := range []struct {
		name, ip, path string
		h              http.Handler
		header         map[string]string
		status         int
		want           float64
	}{
		{"a POST the WAF refused", "198.51.100.240", "/login?user=admin%27%20OR%201%3D1--",
			routeChain(answer200, waf), form, http.StatusForbidden, 0},
		{"a POST to a trap path", "198.51.100.241", "/wp-login.php",
			routeChain(answer200, trap), form, http.StatusForbidden, 0},
		{"a backend's login form refusing a password", "198.51.100.242", "/login",
			routeChain(answer401, waf), form, http.StatusUnauthorized, 1},
		{"Basic auth refusing a password", "198.51.100.243", "/reports",
			routeChain(answer200, BasicAuth("admin", "right-password")),
			map[string]string{"Authorization": "Basic YWRtaW46Z3Vlc3M="}, http.StatusUnauthorized, 1},
		{"a forward-auth service refusing a login", "198.51.100.244", "/login",
			routeChain(answer200, forward), form, http.StatusUnauthorized, 1},
	} {
		code, got := countedRefusal(tc.h, tc.ip, http.MethodPost, tc.path, tc.header)
		if code != tc.status {
			t.Fatalf("%s: answered %d, want %d; the case proves nothing", tc.name, code, tc.status)
		}
		if got != tc.want {
			t.Errorf("%s (%d): %v refused credential attempts counted, want %v", tc.name, code, got, tc.want)
		}
	}
}
