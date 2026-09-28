// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
)

func TestRequirePermission(t *testing.T) {
	tests := []struct {
		name     string
		claims   *auth.Claims
		waived   bool
		action   auth.Action
		resource auth.Resource
		wantOK   bool
		wantCode int
	}{
		{
			// No claims and no mark from the base handler: the request reached
			// the check some other way -- gRPC on a plaintext TCP entrypoint
			// did -- and nobody is not "auth disabled". ADR 0027.
			name:     "nil claims without the base handler's waiver refused",
			claims:   nil,
			action:   auth.ActionWrite,
			resource: auth.ResourceRoutes,
			wantOK:   false,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "nil claims the base handler waived allows (auth disabled)",
			claims:   nil,
			waived:   true,
			action:   auth.ActionWrite,
			resource: auth.ResourceRoutes,
			wantOK:   true,
		},
		{
			name:     "admin write routes allowed",
			claims:   &auth.Claims{ID: "1", Username: "admin", Role: auth.RoleAdmin},
			action:   auth.ActionWrite,
			resource: auth.ResourceRoutes,
			wantOK:   true,
		},
		{
			name:     "viewer write routes forbidden",
			claims:   &auth.Claims{ID: "2", Username: "viewer", Role: auth.RoleViewer},
			action:   auth.ActionWrite,
			resource: auth.ResourceRoutes,
			wantOK:   false,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "viewer read routes allowed",
			claims:   &auth.Claims{ID: "2", Username: "viewer", Role: auth.RoleViewer},
			action:   auth.ActionRead,
			resource: auth.ResourceRoutes,
			wantOK:   true,
		},
		{
			name:     "operator write users forbidden",
			claims:   &auth.Claims{ID: "3", Username: "op", Role: auth.RoleOperator},
			action:   auth.ActionWrite,
			resource: auth.ResourceUsers,
			wantOK:   false,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "operator write routes allowed",
			claims:   &auth.Claims{ID: "3", Username: "op", Role: auth.RoleOperator},
			action:   auth.ActionWrite,
			resource: auth.ResourceRoutes,
			wantOK:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.claims != nil {
				ctx = context.WithValue(ctx, middleware.UserContextKey, tt.claims)
			}
			if tt.waived {
				ctx = middleware.WithAuthNotRequired(ctx)
			}
			r := httptest.NewRequest(http.MethodPut, "/v1/routes", nil).WithContext(ctx)
			w := httptest.NewRecorder()

			ok := RequirePermission(w, r, tt.action, tt.resource)

			if ok != tt.wantOK {
				t.Errorf("RequirePermission() = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK && tt.wantCode != 0 {
				if w.Code != tt.wantCode {
					t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
				}
			}
		})
	}
}

// TestNobodyWithoutAWaiverGetsTheRestrictedView: a read shaped by what the
// caller could change -- the global config and its credentials -- treated a
// request with no claims as "auth disabled" and gave it the full view. Now no
// claims is nobody unless the base handler waived authentication. ADR 0027.
func TestNobodyWithoutAWaiverGetsTheRestrictedView(t *testing.T) {
	bare := httptest.NewRequest(http.MethodGet, "/v1/global", nil)
	if callerMayWrite(bare, auth.ResourceGlobal) {
		t.Error("a request with no claims and no waiver from the base handler was given the full view")
	}
	if !callerMayWrite(authWaived(bare), auth.ResourceGlobal) {
		t.Error("a request the base handler waived (auth off) lost the full view")
	}
}
