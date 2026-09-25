// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestDashboardKeepsItsOwnSecurityHeaders: the entrypoint no longer applies a
// security-header preset to every response, because proxied pages are the
// backend's to secure. The dashboard is the gateway's, and BaseHandler gives it
// its own -- this pins that the entrypoint's preset was never the only one.
func TestDashboardKeepsItsOwnSecurityHeaders(t *testing.T) {
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>dashboard</html>"))
	})
	deps := BaseHandlerDeps{
		ProxyHandler: http.NotFoundHandler(),
		RouteStore:   &mockRouteStore{},
		GlobalReg: &mockGlobalReg{config: &gateonv1.GlobalConfig{
			Management: &gateonv1.ManagementConfig{AllowPublicManagement: true},
		}},
	}
	h := CreateBaseHandler(ui, deps, nil, http.NewServeMux())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("dashboard CSP = %q, want the gateway's own policy", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("dashboard response without nosniff")
	}
}
