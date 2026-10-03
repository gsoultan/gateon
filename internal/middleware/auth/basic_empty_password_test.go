// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"strings"
	"testing"
)

// A user in the list with no password is what the dashboard's "Add user" row
// saved when the password was left blank, and it let anyone in under that
// name: the verifier compared "" with "" (2026-10-02 truth T2). The list is
// refused, with the user's name and why, so the save that would store it fails
// and a stored one fails to build, which the router serves as a refusal
// (ADR 0043). A user with no name is refused for the same reason.
func TestBasicAuthUsersRefusesAUserWithNoPassword(t *testing.T) {
	for _, tc := range []struct{ users, want string }{
		{"alice:pw1,user2:", `user "user2" has no password`},
		{"user2:", `user "user2" has no password`},
		{"alice:pw1, bob: ", `user "bob" has no password`},
		{":pw1", "entry 1 has no user name"},
	} {
		mw, err := BasicAuthUsersWithConfig(tc.users, "", AuthBaseConfig{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("users %q: got %v, want an error containing %q", tc.users, err, tc.want)
			continue
		}
		if mw != nil {
			t.Errorf("users %q: a middleware was returned with the error", tc.users)
		}
	}
}

// The refusal must not repeat a password it was handed: the message reaches
// the API response and the log. "alicepw1" has no colon, so the whole entry
// may be a password typed without its user name.
func TestBasicAuthUsersErrorsDoNotEchoAPassword(t *testing.T) {
	_, err := BasicAuthUsersWithConfig("alicepw1", "", AuthBaseConfig{})
	if err == nil || strings.Contains(err.Error(), "alicepw1") {
		t.Fatalf("got %v, want a refusal that does not quote the entry", err)
	}
}

// A request with an empty password never authenticates, whatever the
// configured check would say: an empty secret is not a credential. Pinned
// against an authenticator that accepts everything, so it is the request-time
// guard that is tested, not the build-time refusal in front of it.
func TestARequestWithAnEmptyPasswordNeverAuthenticates(t *testing.T) {
	acceptAll := basicAuthenticator{realm: "Gateon", verify: func(string, string) bool { return true }}.middleware
	for _, tc := range []struct{ user, pass string }{{"user2", ""}, {"", "pw"}, {"", ""}} {
		if rr := serveBasic(acceptAll(okHandler()), tc.user, tc.pass, true); rr.Code != http.StatusUnauthorized {
			t.Errorf("%q:%q got %d, want 401", tc.user, tc.pass, rr.Code)
		}
	}
	if rr := serveBasic(acceptAll(okHandler()), "alice", "pw1", true); rr.Code != http.StatusOK {
		t.Errorf("a non-empty login got %d through an accept-all check, want 200", rr.Code)
	}
}
