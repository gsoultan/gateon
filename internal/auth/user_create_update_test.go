// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"strconv"
	"sync"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// takeoverPassword is what a refused write tried to set. It must never open
// an account.
const takeoverPassword = "takeover-password"

// assertAccount fails unless username is exactly one account, with id and
// role, that signs in with password and not with takeoverPassword.
func (e engineManager) assertAccount(t *testing.T, username, id, role, password string) {
	t.Helper()
	users, _, err := e.m.ListUsers(0, 100, username)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	var found []*gateonv1.User
	for _, u := range users {
		if u.Username == username {
			found = append(found, u)
		}
	}
	if len(found) != 1 || found[0].Id != id || found[0].Role != role {
		t.Errorf("accounts named %s: %v, want one with id %s and role %s", username, found, id, role)
	}
	if _, _, err := e.m.Authenticate(username, password, ""); err != nil {
		t.Errorf("%s no longer signs in with its own password: %v", username, err)
	}
	if _, _, err := e.m.Authenticate(username, takeoverPassword, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the refused write's password opens %s: err %v", username, err)
	}
}

// TestAddingAUserUnderATakenNameLeavesTheAccountAlone is the regression test
// for Add User taking over an existing account.
//
// Root cause: creates and edits shared one statement, INSERT ... ON
// CONFLICT(username) DO UPDATE SET password, role, so a create under a
// username that existed replaced that account's password and role and
// reported success.
func TestAddingAUserUnderATakenNameLeavesTheAccountAlone(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		alice := e.name("alice")
		id := e.create(t, alice, "alices-password", RoleViewer)
		session := e.signIn(t, alice, "alices-password")

		for name, u := range map[string]*gateonv1.User{
			"with no id":         {Username: alice, Password: takeoverPassword, Role: RoleAdmin},
			"with an unknown id": {Id: "fresh-" + alice, Username: alice, Password: takeoverPassword, Role: RoleAdmin},
		} {
			if err := e.m.UpsertUser(u); !errors.Is(err, ErrUsernameTaken) {
				t.Errorf("a create %s under a taken username: err %v, want ErrUsernameTaken", name, err)
			}
		}
		e.assertAccount(t, alice, id, RoleViewer, "alices-password")
		if _, err := e.m.VerifyToken(session); err != nil {
			t.Errorf("a refused create ended the existing account's session: %v", err)
		}
	})
}

// TestRenamingOntoATakenNameIsRefused: an edit writes by id, and one that
// renames an account onto another's username is refused and changes neither.
func TestRenamingOntoATakenNameIsRefused(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		alice, bob := e.name("alice"), e.name("bob")
		aliceID := e.create(t, alice, "alices-password", RoleViewer)
		bobID := e.create(t, bob, "the-other-accounts-pw", RoleOperator)

		err := e.m.UpsertUser(&gateonv1.User{Id: bobID, Username: alice, Password: takeoverPassword, Role: RoleAdmin})
		if !errors.Is(err, ErrUsernameTaken) {
			t.Errorf("renaming bob onto alice: err %v, want ErrUsernameTaken", err)
		}
		e.assertAccount(t, alice, aliceID, RoleViewer, "alices-password")
		e.assertAccount(t, bob, bobID, RoleOperator, "the-other-accounts-pw")
	})
}

// TestEditsWriteByID pins what an edit may still do: change the role, rename
// to a free username, and set a new password -- leaving the password alone
// when none is given. A rename used to fail outright: the upsert inserted the
// row again and collided with its own id.
func TestEditsWriteByID(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		carol := e.name("carol")
		id := e.create(t, carol, "carols-password", RoleViewer)
		renamed := carol + "-renamed"

		if err := e.m.UpsertUser(&gateonv1.User{Id: id, Username: renamed, Role: RoleOperator}); err != nil {
			t.Fatalf("renaming carol and making her an operator: %v", err)
		}
		e.assertAccount(t, renamed, id, RoleOperator, "carols-password")

		if err := e.m.UpsertUser(&gateonv1.User{Id: id, Username: renamed, Password: "carols-new-password", Role: RoleOperator}); err != nil {
			t.Fatalf("resetting carol's password: %v", err)
		}
		e.assertAccount(t, renamed, id, RoleOperator, "carols-new-password")
	})
}

// TestACreateMayNameItsID: an id nobody has is a create, under that id.
func TestACreateMayNameItsID(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		erin := e.name("erin")
		id := "chosen-" + erin
		if err := e.m.UpsertUser(&gateonv1.User{Id: id, Username: erin, Password: "erins-password", Role: RoleViewer}); err != nil {
			t.Fatalf("creating erin under a chosen id: %v", err)
		}
		t.Cleanup(func() { _ = e.m.DeleteUser(id) })
		e.assertAccount(t, erin, id, RoleViewer, "erins-password")
	})
}

// TestRacingCreatesForOneNameMakeOneAccount: the table's unique constraint,
// not a lookup beforehand, refuses the duplicate -- so of several creates
// racing for one username exactly one succeeds and the rest are refused.
func TestRacingCreatesForOneNameMakeOneAccount(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		name := e.name("frank")
		const racers = 6
		errs := make([]error, racers)
		ids := make([]string, racers)
		var wg sync.WaitGroup
		for i := range racers {
			wg.Go(func() {
				u := &gateonv1.User{Username: name, Password: "racing-passphrase-" + strconv.Itoa(i), Role: RoleViewer}
				errs[i] = e.m.UpsertUser(u)
				ids[i] = u.Id
			})
		}
		wg.Wait()

		won := 0
		for i, err := range errs {
			switch {
			case err == nil:
				won++
				t.Cleanup(func() { _ = e.m.DeleteUser(ids[i]) })
			case !errors.Is(err, ErrUsernameTaken):
				t.Errorf("racer %d: err %v, want success or ErrUsernameTaken", i, err)
			}
		}
		if won != 1 {
			t.Errorf("%d of %d racing creates for one username succeeded, want exactly 1", won, racers)
		}
	})
}
