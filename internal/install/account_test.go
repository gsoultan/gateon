// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"errors"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"
)

// fakeAccounts replaces the two seams ensureServiceUser uses, so the tests
// never create a real account. Not parallel: the seams are package state.
func fakeAccounts(t *testing.T, lookup func(string) (*user.User, error), useradd func(...string) error) {
	t.Helper()
	oldLookup, oldUseradd := lookupAccount, runUseradd
	t.Cleanup(func() { lookupAccount, runUseradd = oldLookup, oldUseradd })
	lookupAccount, runUseradd = lookup, useradd
}

var gateonAccount = &user.User{Username: serviceUser, Uid: "999", Gid: "998"}

func TestEnsureServiceUserReusesAnExistingAccount(t *testing.T) {
	fakeAccounts(t,
		func(string) (*user.User, error) { return gateonAccount, nil },
		func(...string) error {
			t.Error("useradd ran although the account already exists; every upgrade would try to create it again")
			return nil
		})

	uid, gid, err := ensureServiceUser()
	if err != nil || uid != 999 || gid != 998 {
		t.Fatalf("ensureServiceUser = %d, %d, %v; want 999, 998, nil", uid, gid, err)
	}
}

func TestEnsureServiceUserCreatesTheAccountItLacks(t *testing.T) {
	created := false
	var args []string
	fakeAccounts(t,
		func(string) (*user.User, error) {
			if !created {
				return nil, user.UnknownUserError(serviceUser)
			}
			return gateonAccount, nil
		},
		func(a ...string) error {
			created, args = true, a
			return nil
		})

	uid, gid, err := ensureServiceUser()
	if err != nil || uid != 999 || gid != 998 {
		t.Fatalf("ensureServiceUser = %d, %d, %v; want 999, 998, nil", uid, gid, err)
	}
	if want := useraddArgs(nologinShell()); !slices.Equal(args, want) {
		t.Errorf("useradd ran with %q, want %q -- the flags scripts/postinstall.sh uses", args, want)
	}
}

func TestEnsureServiceUserReportsAFailedUseradd(t *testing.T) {
	fakeAccounts(t,
		func(string) (*user.User, error) { return nil, user.UnknownUserError(serviceUser) },
		func(...string) error { return errors.New("useradd: Permission denied") })

	if _, _, err := ensureServiceUser(); err == nil || !strings.Contains(err.Error(), serviceUser) {
		t.Fatalf("ensureServiceUser = %v; want an error naming the %s account", err, serviceUser)
	}
}

func TestAccountIDsRefusesNonNumericIDs(t *testing.T) {
	for _, u := range []*user.User{
		{Username: serviceUser, Uid: "not-a-number", Gid: "998"},
		{Username: serviceUser, Uid: "999", Gid: "not-a-number"},
	} {
		if _, _, err := accountIDs(u); err == nil {
			t.Errorf("accountIDs(uid %q, gid %q) returned no error; a bad id must not become 0, which is root",
				u.Uid, u.Gid)
		}
	}
}

// TestNologinShellExistsOrIsFalse: the account's shell must be a program that
// refuses a login, and one this host has.
func TestNologinShellExistsOrIsFalse(t *testing.T) {
	shell := nologinShell()
	if shell == "/bin/false" {
		return
	}
	if _, err := os.Stat(shell); err != nil {
		t.Errorf("nologinShell = %s, which does not exist: %v", shell, err)
	}
}
