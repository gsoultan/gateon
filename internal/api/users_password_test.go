// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ownAccount is an ApiService over a real auth.Manager with one administrator,
// and a context signed in as that administrator -- what the gRPC transport
// hands ApiService.ChangePassword, which has no REST handler in front of it.
func ownAccount(t *testing.T) (*ApiService, context.Context, string) {
	t.Helper()
	m, err := auth.NewManager(filepath.Join(t.TempDir(), "auth.db"), "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	u := &gateonv1.User{Username: "alice", Password: "right-pass", Role: auth.RoleAdmin}
	if err := m.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	ctx := context.WithValue(t.Context(), middleware.UserContextKey,
		&auth.Claims{ID: u.Id, Username: "alice", Role: auth.RoleAdmin})
	return &ApiService{Auth: m}, ctx, u.Id
}

// TestChangePasswordRPCAsksForTheCurrentPassword: gRPC serves ChangePassword
// straight from ApiService, so the step-up has to live here, and a refusal has
// to carry a code the transports turn into something other than "signed out".
func TestChangePasswordRPCAsksForTheCurrentPassword(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		want          codes.Code
	}{
		{"no current password", "", codes.InvalidArgument},
		{"a wrong one", "wrong-pass", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, ctx, id := ownAccount(t)
			_, err := svc.ChangePassword(ctx, &gateonv1.ChangePasswordRequest{Id: id, Password: "new-pass", CurrentPassword: tc.current})
			if status.Code(err) != tc.want {
				t.Errorf("err = %v, want code %s", err, tc.want)
			}
			if _, _, err := svc.Auth.Authenticate("alice", "right-pass"); err != nil {
				t.Errorf("the password changed anyway: %v", err)
			}
		})
	}
}

// TestChangePasswordRPCLocksLikeSignIn: after the sign-in limit of wrong current
// passwords the account is locked, and the RPC says so with ResourceExhausted.
func TestChangePasswordRPCLocksLikeSignIn(t *testing.T) {
	svc, ctx, id := ownAccount(t)
	for range auth.MaxFailedAttempts {
		_, _ = svc.ChangePassword(ctx, &gateonv1.ChangePasswordRequest{Id: id, Password: "new-pass", CurrentPassword: "wrong-pass"})
	}
	_, err := svc.ChangePassword(ctx, &gateonv1.ChangePasswordRequest{Id: id, Password: "new-pass", CurrentPassword: "right-pass"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("err = %v, want ResourceExhausted", err)
	}
}

// TestChangePasswordRPCWithTheCurrentPassword pins the path the fix keeps.
func TestChangePasswordRPCWithTheCurrentPassword(t *testing.T) {
	svc, ctx, id := ownAccount(t)
	resp, err := svc.ChangePassword(ctx, &gateonv1.ChangePasswordRequest{Id: id, Password: "new-pass", CurrentPassword: "right-pass"})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("resp = %v, err = %v", resp, err)
	}
	if _, _, err := svc.Auth.Authenticate("alice", "new-pass"); err != nil {
		t.Errorf("the new password does not sign in: %v", err)
	}
}

// TestUpdateUserRPCCannotSetTheCallersPassword: UpdateUser writes a password
// when the user it is given has one; for the caller's own account that would
// walk around ChangePassword's step-up. By id it is refused as such. A fresh
// id with the caller's username used to land on the caller's account too; it
// is a create now, which the taken username refuses.
func TestUpdateUserRPCCannotSetTheCallersPassword(t *testing.T) {
	svc, ctx, id := ownAccount(t)
	for _, tc := range []struct {
		u    *gateonv1.User
		want codes.Code
	}{
		{&gateonv1.User{Id: id, Username: "alice", Role: auth.RoleAdmin, Password: "new-pass"}, codes.PermissionDenied},
		{&gateonv1.User{Id: "fresh-id", Username: "alice", Role: auth.RoleAdmin, Password: "new-pass"}, codes.AlreadyExists},
	} {
		if _, err := svc.UpdateUser(ctx, &gateonv1.UpdateUserRequest{User: tc.u}); status.Code(err) != tc.want {
			t.Errorf("UpdateUser(id %q) err = %v, want %s", tc.u.GetId(), err, tc.want)
		}
	}
	if _, _, err := svc.Auth.Authenticate("alice", "right-pass"); err != nil {
		t.Errorf("the password changed anyway: %v", err)
	}
}
