// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTheBaseHandlerWaivesAuthenticationOnlyWhereItDecidesTo: the permission
// checks now refuse a request that carries no claims unless the base handler
// marked it as needing none (ADR 0027). So the base handler must mark exactly
// its no-credential branches -- authentication off for the deployment, and the
// paths that work before a session exists -- or an auth-off gateway refuses its
// own API and sign-in breaks; and it must not mark anything else.
func TestTheBaseHandlerWaivesAuthenticationOnlyWhereItDecidesTo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		epID       string
		path       string
		authOn     bool
		wantReach  bool
		wantWaived bool
	}{
		{"auth off, public entrypoint, API", "http-80", "/v1/routes", false, true, true},
		{"management entrypoint, a path that works before a session", "management", "/v1/setup/required", true, true, true},
		{"management entrypoint, a protected path with no auth service", "management", "/v1/routes", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached, waived := false, false
			deps := BaseHandlerDeps{
				ProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached, waived = true, middleware.AuthNotRequired(r.Context())
					w.WriteHeader(http.StatusOK)
				}),
				RouteStore: &mockRouteStore{},
				GlobalReg: &mockGlobalReg{config: &gateonv1.GlobalConfig{
					Auth:       &gateonv1.AuthConfig{Enabled: tc.authOn},
					Management: &gateonv1.ManagementConfig{AllowPublicManagement: true},
				}},
			}
			handler := CreateBaseHandler(http.NotFoundHandler(), deps, nil, nil)

			req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com"+tc.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), middleware.EntryPointIDContextKey, tc.epID))
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if reached != tc.wantReach || waived != tc.wantWaived {
				t.Fatalf("%s %s on %q: reached=%v waived=%v, want reached=%v waived=%v",
					http.MethodGet, tc.path, tc.epID, reached, waived, tc.wantReach, tc.wantWaived)
			}
		})
	}
}
