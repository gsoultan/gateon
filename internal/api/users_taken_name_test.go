// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestUpdateUserRPCRefusesATakenUsername: gRPC serves UpdateUser straight
// from ApiService, so a create under a username that exists has to be refused
// here, with a code the transports carry -- AlreadyExists, which REST answers
// as 409 -- and the existing account left as it was.
func TestUpdateUserRPCRefusesATakenUsername(t *testing.T) {
	svc, ctx, _ := ownAccount(t)
	bob := &gateonv1.User{Username: "bob", Password: "the-other-accounts-pw", Role: auth.RoleViewer}
	if err := svc.Auth.UpsertUser(bob); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	_, err := svc.UpdateUser(ctx, &gateonv1.UpdateUserRequest{
		User: &gateonv1.User{Username: "bob", Password: "takeover-passphrase", Role: auth.RoleAdmin},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("Add User under a taken username: err = %v, want code AlreadyExists", err)
	}
	if _, _, err := svc.Auth.Authenticate("bob", "the-other-accounts-pw", ""); err != nil {
		t.Errorf("bob's password was replaced: %v", err)
	}
	users, _, err := svc.Auth.ListUsers(0, 10, "bob")
	if err != nil || len(users) != 1 || users[0].Id != bob.Id || users[0].Role != auth.RoleViewer {
		t.Errorf("accounts named bob: %v (err %v), want the one viewer created first", users, err)
	}
}
