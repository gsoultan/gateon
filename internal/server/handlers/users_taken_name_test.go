// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAddUserUnderATakenNameIsRefusedWithConflict: PUT /v1/users is both Add
// User and Edit User. Adding a user under a username that existed replaced
// that account's password and role and answered 200, so an administrator who
// typed a colleague's name took the account over. It is 409 now, for a create
// and for an edit that renames onto the name, and the account is left alone.
func TestAddUserUnderATakenNameIsRefusedWithConflict(t *testing.T) {
	f := newStepUpFixture(t)
	bob := &gateonv1.User{Username: "bob", Password: "bobs-pass", Role: auth.RoleViewer}
	carol := &gateonv1.User{Username: "carol", Password: "carols-pass", Role: auth.RoleViewer}
	for _, u := range []*gateonv1.User{bob, carol} {
		if err := f.m.UpsertUser(u); err != nil {
			t.Fatalf("UpsertUser: %v", err)
		}
	}

	for name, body := range map[string]string{
		"Add User":             `{"username":"bob","password":"takeover-pass","role":"admin"}`,
		"a rename onto a name": `{"id":"` + carol.Id + `","username":"bob","password":"takeover-pass","role":"admin"}`,
	} {
		if rr := f.as(t, http.MethodPut, "/v1/users", body); rr.Code != http.StatusConflict {
			t.Errorf("%s under a taken username: status %d, want 409: %s", name, rr.Code, rr.Body.String())
		}
	}
	f.assertPassword(t, "bob", "bobs-pass", "takeover-pass")
	f.assertPassword(t, "carol", "carols-pass", "takeover-pass")
	users, _, err := f.m.ListUsers(0, 10, "bob")
	if err != nil || len(users) != 1 || users[0].Id != bob.Id || users[0].Role != auth.RoleViewer {
		t.Errorf("accounts named bob: %v (err %v), want the one viewer created first", users, err)
	}
}
