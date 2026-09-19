// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestChangePasswordRefusesWhenTheCallerCannotBeRead pins the self-or-admin
// guard against a claims value it cannot assert.
//
// The guard read the context key with a discarded ok and then tested
// `claims != nil && claims.Role != admin && claims.ID != req.Id`. When the
// assertion failed -- the value present but not a *auth.Claims -- claims was
// nil, so the whole condition was false and the function fell through to
// ChangePassword for whatever id the request named. The check that exists to
// stop one account changing another's password was skipped by exactly the
// case it could not identify, while requireAdmin ten lines below denies on
// that same condition. This is the shape CLAUDE.md invariant 5 describes,
// in the one package that invariant's grep does not cover.
//
// InjectContext takes `claims any` and stores whatever it is handed, and the
// JWT middleware hands it jwt.MapClaims, so the unreadable value is reachable
// by construction rather than hypothetical.
func TestChangePasswordRefusesWhenTheCallerCannotBeRead(t *testing.T) {
	svc, victimID := newUsersTestService(t)

	// A claims value of some other type: present, but not assertable.
	ctx := context.WithValue(context.Background(),
		middleware.UserContextKey, map[string]any{"sub": "attacker", "role": "viewer"})

	resp, err := svc.ChangePassword(ctx, &gateonv1.ChangePasswordRequest{
		Id:       victimID,
		Password: "attacker-chosen-password",
	})
	if err == nil {
		t.Errorf("ChangePassword returned no error for a caller whose claims could not be read; resp=%v", resp)
	}

	// The real proof: the victim's password must be unchanged.
	if _, _, authErr := svc.Auth.Authenticate("victim", "attacker-chosen-password"); authErr == nil {
		t.Error("the victim's password was replaced by a caller the guard could not identify")
	}
	if _, _, authErr := svc.Auth.Authenticate("victim", "victim-original-password"); authErr != nil {
		t.Errorf("the victim's original password no longer works: %v", authErr)
	}
}

// TestChangePasswordStillAllowsSelfAndAdmin is the control: the fix must not
// break the two cases the guard is meant to permit.
func TestChangePasswordStillAllowsSelfAndAdmin(t *testing.T) {
	svc, victimID := newUsersTestService(t)

	self := mwauth.InjectContext(context.Background(),
		&auth.Claims{ID: victimID, Role: auth.RoleViewer})
	if _, err := svc.ChangePassword(self, &gateonv1.ChangePasswordRequest{
		Id: victimID, Password: "chosen-by-the-owner",
	}); err != nil {
		t.Fatalf("a user changing their own password was refused: %v", err)
	}

	admin := mwauth.InjectContext(context.Background(),
		&auth.Claims{ID: "someone-else", Role: auth.RoleAdmin})
	if _, err := svc.ChangePassword(admin, &gateonv1.ChangePasswordRequest{
		Id: victimID, Password: "reset-by-an-admin",
	}); err != nil {
		t.Fatalf("an admin resetting another user's password was refused: %v", err)
	}
}

// newUsersTestService returns a service backed by a real auth manager in a
// temp dir, plus the id of a user whose password is "victim-original-password".
func newUsersTestService(t *testing.T) (*ApiService, string) {
	t.Helper()
	tmp := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	u := &gateonv1.User{
		Id:       "victim-id",
		Username: "victim",
		Password: "victim-original-password",
		Role:     auth.RoleViewer,
	}
	if err := mgr.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	return &ApiService{Auth: auth.NewHolder(mgr)}, u.Id
}
