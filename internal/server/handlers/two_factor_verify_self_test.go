// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// verify2FAAPI answers every verification with a session token for the
// account the request names, which is what the real service does on a valid
// code. The test is about who the handler lets ask.
type verify2FAAPI struct {
	GlobalAndAuthAPI

	called bool
	id     string
}

func (s *verify2FAAPI) Verify2FA(_ context.Context, req *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error) {
	s.called = true
	s.id = req.Id
	return &gateonv1.Verify2FAResponse{Success: true, Token: "SESSION-FOR-" + req.Id, User: &gateonv1.User{Id: req.Id}}, nil
}

func claimsRequest(t *testing.T, path, body string, claims *auth.Claims) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))
}

// TestTwoFactorVerifyRefusesAnotherAccount: the verify endpoint takes a user
// id and a code, and on success returns that user's session token in the
// body. The handler only asked whether the caller had a session, not whose,
// so an authenticated viewer holding an administrator's TOTP code -- or one
// of their recovery codes -- was handed an administrator session.
func TestTwoFactorVerifyRefusesAnotherAccount(t *testing.T) {
	svc := &verify2FAAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})

	viewer := &auth.Claims{ID: "the-viewer", Username: "viewer", Role: auth.RoleViewer}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, claimsRequest(t, "/v1/auth/2fa/verify", `{"id":"the-admin","code":"123456"}`, viewer))

	if svc.called {
		t.Errorf("Verify2FA ran for %q on behalf of %q", svc.id, viewer.ID)
	}
	if strings.Contains(rr.Body.String(), "SESSION-FOR-the-admin") {
		t.Errorf("another account's session token was returned to the caller")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rr.Code)
	}
}

// TestTwoFactorVerifyStillServesOwnAccount pins the path the fix must keep:
// an authenticated user finishing their own enrolment.
func TestTwoFactorVerifyStillServesOwnAccount(t *testing.T) {
	svc := &verify2FAAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})

	self := &auth.Claims{ID: "the-viewer", Username: "viewer", Role: auth.RoleViewer}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, claimsRequest(t, "/v1/auth/2fa/verify", `{"id":"the-viewer","code":"123456"}`, self))

	if !svc.called || svc.id != "the-viewer" {
		t.Errorf("own-account verification did not reach the service (called=%v id=%q)", svc.called, svc.id)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
}
