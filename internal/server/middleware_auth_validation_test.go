// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The dashboard's "Add user" row appends "user<N>:" -- a user with no
// password -- and the save stored it, after which anyone who sent that name
// and no password was let in (2026-10-02 truth T2). The save now refuses it on
// REST and gRPC, naming the user, and stores nothing; the users already there
// keep their passwords through the placeholder (ADR 0033), so a new user with
// a password saves as before (ADR 0043).
func TestABasicAuthUserWithNoPasswordIsRefusedAtSave(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		m := a.shown(t, "auth-basic-users")
		m.Config["users"] += ",user4:"
		code, body := a.put(t, m)
		requireRefused(t, "a basic-auth user with no password", code, body, `user4`, "no password")
		a.requireUnchanged(t, "a refused empty password", live, file)
	})
	t.Run("gRPC", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		live, file := a.snapshot(t)
		m := a.shown(t, "auth-basic-users")
		m.Config["users"] += ",user4:"
		_, err := a.grpc.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{Middleware: m})
		if err == nil || !strings.Contains(err.Error(), "user4") {
			t.Fatalf("gRPC UpdateMiddleware with an empty password: %v, want a refusal naming user4", err)
		}
		a.requireUnchanged(t, "a refused empty password", live, file)
	})
	t.Run("a new user with a password, beside kept ones, saves", func(t *testing.T) {
		a, _ := newMwAPI(t, auth.RoleOperator)
		before := usersOf(a.stored(t, "auth-basic-users")["users"])
		m := a.shown(t, "auth-basic-users")
		m.Config["users"] += ",user4:s3cret-four"
		if code, body := a.put(t, m); code != http.StatusOK {
			t.Fatalf("PUT: %d %s", code, body)
		}
		got := usersOf(a.stored(t, "auth-basic-users")["users"])
		if got["user4"] != "s3cret-four" || got["alice"] != before["alice"] || got["bob"] != before["bob"] {
			t.Errorf("stored users %v; want user4's new password and every other user's kept one", got)
		}
	})
}
