// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// resetTwoFactorAPI records the reset the handler asked for, and refuses one
// the way ApiService does, so the status mapping is exercised.
type resetTwoFactorAPI struct {
	GlobalAndAuthAPI
	resetID string
	refuse  error
}

func (s *resetTwoFactorAPI) ResetUserTwoFactor(_ context.Context, req *gateonv1.ResetUserTwoFactorRequest) (*gateonv1.ResetUserTwoFactorResponse, error) {
	s.resetID = req.GetId()
	if s.refuse != nil {
		return nil, s.refuse
	}
	return &gateonv1.ResetUserTwoFactorResponse{Success: true}, nil
}

func postReset(t *testing.T, svc GlobalAndAuthAPI, role string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/users/u-2/2fa/reset", http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "u-1", Username: "someone", Role: role}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestResetTwoFactorOverRESTIsForUserWritersOnly: REST is the third transport
// for the reset (ADR 0057). Its permission is the users resource's write,
// checked before the service is reached.
func TestResetTwoFactorOverRESTIsForUserWritersOnly(t *testing.T) {
	viewer := &resetTwoFactorAPI{}
	if rr := postReset(t, viewer, auth.RoleViewer); rr.Code != http.StatusForbidden || viewer.resetID != "" {
		t.Errorf("a viewer's reset: status %d, reached the service for %q; want 403 before it", rr.Code, viewer.resetID)
	}
	admin := &resetTwoFactorAPI{}
	if rr := postReset(t, admin, auth.RoleAdmin); rr.Code != http.StatusOK || admin.resetID != "u-2" {
		t.Errorf("an administrator's reset: status %d, reset %q; want 200 for u-2", rr.Code, admin.resetID)
	}
}

// TestResetTwoFactorOverRESTSaysWhyItWasRefused: the service's refusals --
// the caller's own account, an unknown account -- are answers, not 500s.
func TestResetTwoFactorOverRESTSaysWhyItWasRefused(t *testing.T) {
	for _, c := range []struct {
		code codes.Code
		want int
	}{
		{codes.PermissionDenied, http.StatusForbidden},
		{codes.NotFound, http.StatusNotFound},
	} {
		svc := &resetTwoFactorAPI{refuse: status.Error(c.code, "refused")}
		if rr := postReset(t, svc, auth.RoleAdmin); rr.Code != c.want {
			t.Errorf("a %s refusal answered %d, want %d", c.code, rr.Code, c.want)
		}
	}
}
