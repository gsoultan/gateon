// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Two handlers make an authorization decision by asserting the context value to
// *auth.Claims, and both skip the decision when the assertion fails:
//
//	if claims, ok := claimsVal.(*auth.Claims); ok && claims != nil {
//	    if claims.ID != req.Id { deny }
//	}
//	// ... and if ok was false, execution simply continues
//
// RequirePermission, five lines away in rbac.go, does the same assertion and
// *denies* when it fails. The two disagree about what an unrecognised claims
// value means, and the fail-open half is on the password change and the 2FA
// enrolment.
//
// This is reachable in principle rather than in the shipped configuration: the
// management plane authenticates with Paseto, whose verifier returns
// *auth.Claims, so the assertion holds today. But there is exactly one context
// key -- middleware.UserContextKey is an alias for auth.UserContextKey -- and
// exactly one writer, InjectContext(ctx, claims any), which stores whatever it
// is handed. The JWT middleware hands it jwt.MapClaims. Nothing in the type
// system keeps those apart, and the difference between the two spellings above
// is whether that mistake is a 403 or an account takeover.
//
// CLAUDE.md's first security invariant exists for this exact shape: a nil-ish
// check that reads as "auth is present" at the moment it is not.

// mapClaimsRequest builds a request carrying jwt.MapClaims -- a real type this
// codebase stores under this key -- rather than *auth.Claims.
func mapClaimsRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		jwt.MapClaims{"sub": "attacker", "id": "attacker"}))
}

// TestPasswordChangeDeniesUnrecognisedClaims covers the password endpoint.
//
// The handler allows the change when the caller is an admin or is changing their
// own password. With a claims value it cannot read it establishes neither, and
// proceeds anyway -- so the request changes the password of whatever user id it
// names.
func TestPasswordChangeDeniesUnrecognisedClaims(t *testing.T) {
	svc := &failOpenAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})

	req := mapClaimsRequest(t, http.MethodPost, "/v1/users/password",
		`{"id":"the-admin-user","password":"attacker-chosen"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if svc.changePasswordCalled {
		t.Errorf("the password of %q was changed by a caller whose claims could not "+
			"be read (got %d).\nThe handler establishes neither admin nor self, and "+
			"continues regardless: `if claims, ok := v.(*auth.Claims); ok && ...` "+
			"skips its own check when ok is false. RequirePermission does the same "+
			"assertion and denies. An unreadable credential is not a credential.",
			svc.changePasswordID, rr.Code)
	}
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 or 403", rr.Code)
	}
}

// TestTwoFactorSetupDeniesUnrecognisedClaims covers the 2FA endpoint.
//
// This one is worse, and the handler's own comment says why: the response
// carries the TOTP secret, the QR code and the recovery codes, so setting up 2FA
// for another account hands over its second factor. The comment is explicit that
// even an admin must not be able to do this -- and the check it guards is
// skipped entirely when the claims value is not the expected type.
func TestTwoFactorSetupDeniesUnrecognisedClaims(t *testing.T) {
	svc := &failOpenAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})

	req := mapClaimsRequest(t, http.MethodPost, "/v1/auth/2fa/setup",
		`{"id":"the-admin-user"}`)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if svc.setup2FACalled {
		t.Errorf("2FA was set up for %q by a caller whose claims could not be read "+
			"(got %d).\nThe response to this call contains that account's TOTP "+
			"secret and recovery codes, which is the account. The handler's own "+
			"comment says even an admin must not reach here for another user; a "+
			"failed type assertion does.", svc.setup2FAID, rr.Code)
	}
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 or 403", rr.Code)
	}
}

// TestSelfServiceStillWorks is the control.
//
// Denying an unreadable claims value must not become denying the legitimate
// self-service case these endpoints exist for.
func TestSelfServiceStillWorks(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		called           func(*failOpenAPI) bool
	}{
		{"password", "/v1/users/password", `{"id":"user-1","password":"new-one"}`,
			func(s *failOpenAPI) bool { return s.changePasswordCalled }},
		{"2fa setup", "/v1/auth/2fa/setup", `{"id":"user-1"}`,
			func(s *failOpenAPI) bool { return s.setup2FACalled }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &failOpenAPI{}
			mux := http.NewServeMux()
			registerGlobalHandlers(mux, svc, &Deps{})

			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
				&auth.Claims{ID: "user-1", Username: "user", Role: auth.RoleViewer}))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if !tc.called(svc) {
				t.Errorf("a user acting on their own account was refused (%d); the "+
					"fail-closed change has broken the self-service path these "+
					"endpoints exist for", rr.Code)
			}
		})
	}
}

// failOpenAPI records whether the privileged operation was reached. The embedded
// interface is nil on purpose: anything these handlers call that is not
// implemented here panics and names itself, rather than quietly returning a zero
// value and making the test assert against the wrong thing.
type failOpenAPI struct {
	GlobalAndAuthAPI

	changePasswordCalled bool
	changePasswordID     string
	setup2FACalled       bool
	setup2FAID           string
}

func (s *failOpenAPI) ChangePassword(_ context.Context, req *gateonv1.ChangePasswordRequest) (*gateonv1.ChangePasswordResponse, error) {
	s.changePasswordCalled = true
	s.changePasswordID = req.Id
	return &gateonv1.ChangePasswordResponse{Success: true}, nil
}

func (s *failOpenAPI) Setup2FA(_ context.Context, req *gateonv1.Setup2FARequest) (*gateonv1.Setup2FAResponse, error) {
	s.setup2FACalled = true
	s.setup2FAID = req.Id
	return &gateonv1.Setup2FAResponse{Secret: "TOTP-SECRET-FOR-" + req.Id}, nil
}

// TestUnauthenticatedEndpointsBoundTheirBody pins a limit that was the wrong way
// round.
//
// The outer handler caps every request at 10 MiB, so nothing here was unbounded
// — that hypothesis was checked and is wrong. What was true is that the shared
// decoders bound authenticated requests to 1 MiB while /v1/setup and
// /v1/auth/2fa/enroll, the two management paths that skip authentication
// entirely, decoded straight from r.Body and so got the looser 10 MiB. The
// tightest limit belonged in front of the least-trusted callers, not behind
// them.
func TestUnauthenticatedEndpointsBoundTheirBody(t *testing.T) {
	svc := &failOpenAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})

	// A syntactically valid JSON document larger than the 1 MiB bound. Truncated
	// mid-string by the limit reader, it cannot parse, which is the observable
	// consequence of the bound being applied.
	oversize := `{"username":"` + strings.Repeat("A", MaxRequestBodySize+1024) + `"}`

	// Only /v1/setup is driven here. /v1/auth/2fa/enroll carries the identical
	// bound but checks auth.Available before decoding — correct ordering, and it
	// means the decode is unreachable without a configured auth manager, which
	// this test deliberately does not stand up.
	for _, path := range []string{"/v1/setup"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(oversize))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("a %d-byte body to an unauthenticated endpoint got %d, want 400. "+
					"These two paths skip authentication, so they should carry the "+
					"tightest body limit on the management plane rather than the "+
					"loosest.", len(oversize), rr.Code)
			}
		})
	}
}
