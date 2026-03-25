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
		action   auth.Action
		resource auth.Resource
		wantOK   bool
		wantCode int
	}{
		{
			name:     "nil claims allows (auth disabled)",
			claims:   nil,
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
