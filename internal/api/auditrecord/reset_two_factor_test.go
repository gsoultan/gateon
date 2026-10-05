// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auditrecord_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// twoAccounts is an ApiService over a real user database holding an
// administrator and an operator who is signed in; it returns the service, the
// administrator's context, and the operator's id and session.
func twoAccounts(t *testing.T) (svc *api.ApiService, admin context.Context, userID, session string) {
	t.Helper()
	m, err := auth.NewManager(filepath.Join(t.TempDir(), "auth.db"), "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	a := &gateonv1.User{Username: "admin", Password: "correct-horse-battery-1", Role: auth.RoleAdmin}
	u := &gateonv1.User{Username: "operator", Password: "correct-horse-battery-2", Role: auth.RoleOperator}
	for _, x := range []*gateonv1.User{a, u} {
		if err := m.UpsertUser(x); err != nil {
			t.Fatalf("UpsertUser: %v", err)
		}
	}
	session, _, err = m.Authenticate("operator", "correct-horse-battery-2", "")
	if err != nil {
		t.Fatalf("the operator signs in: %v", err)
	}
	admin = context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: a.Id, Username: "admin", Role: auth.RoleAdmin})
	return &api.ApiService{Auth: m}, admin, u.Id, session
}

// TestResetUserTwoFactorIsAuditedAndEndsTheSessions is MGMT-N5 through the
// service every transport calls: the reset is recorded under the
// administrator who made it, naming the account, and the account's session
// ends with it.
func TestResetUserTwoFactorIsAuditedAndEndsTheSessions(t *testing.T) {
	svc, admin, userID, session := twoAccounts(t)
	resp, err := svc.ResetUserTwoFactor(admin, &gateonv1.ResetUserTwoFactorRequest{Id: userID})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("an administrator resetting another account: resp=%v err=%v", resp, err)
	}
	if _, err := svc.Auth.VerifyToken(session); err == nil {
		t.Error("the account's session survived the reset")
	}
	claims, _ := admin.Value(middleware.UserContextKey).(*auth.Claims)
	var recorded bool
	for _, e := range entriesBy(t, claims.ID) {
		if e.Action == "reset_2fa" && e.Resource == "user" && strings.Contains(e.Details, userID) {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("no reset_2fa entry naming %s under the administrator %s", userID, claims.ID)
	}
}

// TestResetUserTwoFactorRefuses: not the caller's own account (that is
// self-service, behind the password), not for an operator, not an account
// that does not exist -- and a refusal records nothing.
func TestResetUserTwoFactorRefuses(t *testing.T) {
	svc, admin, userID, _ := twoAccounts(t)
	claims, _ := admin.Value(middleware.UserContextKey).(*auth.Claims)
	operator := context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: userID, Username: "operator", Role: auth.RoleOperator})
	for _, c := range []struct {
		name string
		ctx  context.Context
		id   string
		want codes.Code
	}{
		{"own account", admin, claims.ID, codes.PermissionDenied},
		{"an operator", operator, "someone-else", codes.PermissionDenied},
		{"no such account", admin, "no-such-account", codes.NotFound},
		{"no account named", admin, "", codes.InvalidArgument},
	} {
		if _, err := svc.ResetUserTwoFactor(c.ctx, &gateonv1.ResetUserTwoFactorRequest{Id: c.id}); status.Code(err) != c.want {
			t.Errorf("%s: err = %v, want %s", c.name, err, c.want)
		}
	}
	for _, e := range entriesBy(t, claims.ID) {
		if e.Action == "reset_2fa" {
			t.Errorf("a refused reset was recorded as done: %q", e.Details)
		}
	}
}
