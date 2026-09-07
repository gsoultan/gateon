// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Basic Auth family shipped with no tests at all — BasicAuth,
// BasicAuthWithRealm, BasicAuthWithConfig, BasicAuthUsers and
// BasicAuthUsersWithConfig were all at 0% coverage in a package whose history
// includes two authentication bypasses.
//
// The method that found defects in six other packages applies here: every one of
// those was an *absence* — a missing column, a missing threshold, a missing
// tie-break — and nothing on the screen to react to. Only exercising the
// behaviour surfaces an absence.

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
	})
}

// serveBasic drives one request, optionally with credentials.
func serveBasic(h http.Handler, user, pass string, withCreds bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if withCreds {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestBasicAuthAcceptsOnlyTheConfiguredCredentials is the baseline.
func TestBasicAuthAcceptsOnlyTheConfiguredCredentials(t *testing.T) {
	h := BasicAuth("alice", "correct-horse")(okHandler())

	for _, tc := range []struct {
		name, user, pass string
		creds            bool
		want             int
	}{
		{"correct", "alice", "correct-horse", true, http.StatusOK},
		{"wrong password", "alice", "wrong", true, http.StatusUnauthorized},
		{"wrong user", "bob", "correct-horse", true, http.StatusUnauthorized},
		{"both wrong", "bob", "wrong", true, http.StatusUnauthorized},
		{"no credentials at all", "", "", false, http.StatusUnauthorized},
		{"empty credentials", "", "", true, http.StatusUnauthorized},
		{"password as username", "correct-horse", "alice", true, http.StatusUnauthorized},
		{"prefix of the password", "alice", "correct", true, http.StatusUnauthorized},
		{"password with trailing byte", "alice", "correct-horse ", true, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := serveBasic(h, tc.user, tc.pass, tc.creds).Code; got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestBasicAuthRefusesEmptyConfiguredCredentials is the one worth arguing about.
//
// BasicAuthUsers validates its input and refuses to build from an empty user
// list. BasicAuth took a username and a password as two strings and validated
// neither, so BasicAuth("", "") built a middleware that authenticated anyone
// presenting those same empty values — one header away for an attacker who tries
// it, while reading in a config file as "basic auth is enabled".
//
// Scope, stated plainly: **no shipped configuration reached it.** auth_factory.go
// refuses `basic` auth with an empty username or password, so this was a hazard
// in an exported constructor rather than a live bypass. It is fixed anyway,
// because these are exported and a guarantee that holds only while every caller
// remembers is the kind this project has already been bitten by — the first-run
// auth bypass and the transport RBAC gap were both of that shape.
//
// A credential that is empty is not a credential. The sibling function already
// takes that position; this pins that the whole family does.
func TestBasicAuthRefusesEmptyConfiguredCredentials(t *testing.T) {
	for _, tc := range []struct{ name, user, pass string }{
		{"both empty", "", ""},
		{"empty password", "alice", ""},
		{"empty username", "", "correct-horse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := BasicAuth(tc.user, tc.pass)(okHandler())

			// The exact credentials the misconfiguration would accept.
			rr := serveBasic(h, tc.user, tc.pass, true)
			if rr.Code == http.StatusOK {
				t.Errorf("BasicAuth(%q, %q) authenticated a request presenting those "+
					"same values.\nAn empty username or password is a misconfiguration, "+
					"not a credential, and this one reads as 'basic auth is enabled' "+
					"while admitting anyone who guesses it. BasicAuthUsers already "+
					"refuses to build from empty input; the single-user form must too.",
					tc.user, tc.pass)
			}
		})
	}
}

// TestBasicAuthChallengesWithTheConfiguredRealm covers the header a browser
// needs to prompt.
//
// Without WWW-Authenticate the browser shows a bare 401 and never offers a login
// box, so the endpoint is unreachable rather than protected.
func TestBasicAuthChallengesWithTheConfiguredRealm(t *testing.T) {
	rr := serveBasic(BasicAuthWithRealm("alice", "pw", "Staging")(okHandler()), "", "", false)
	if got := rr.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="Staging"`) {
		t.Errorf("WWW-Authenticate = %q, want it to carry realm=\"Staging\"", got)
	}

	// An empty realm falls back rather than emitting realm="".
	rr = serveBasic(BasicAuthWithRealm("alice", "pw", "")(okHandler()), "", "", false)
	if got := rr.Header().Get("WWW-Authenticate"); !strings.Contains(got, `realm="Gateon"`) {
		t.Errorf("with no realm configured, WWW-Authenticate = %q, want the default", got)
	}
}

// TestBasicAuthUsersParsing covers the multi-user form's input handling.
func TestBasicAuthUsersParsing(t *testing.T) {
	for _, tc := range []struct {
		name, users string
		wantErr     bool
	}{
		{"single pair", "alice:pw1", false},
		{"several pairs", "alice:pw1,bob:pw2", false},
		{"spaces around pairs", " alice:pw1 , bob:pw2 ", false},
		{"password containing a colon", "alice:pw:with:colons", false},
		{"empty", "", true},
		{"no colon", "alice", true},
		{"only separators", ",,,", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BasicAuthUsers(tc.users, "Gateon")
			if (err != nil) != tc.wantErr {
				t.Fatalf("BasicAuthUsers(%q) error = %v, wantErr %v", tc.users, err, tc.wantErr)
			}
		})
	}
}

// TestBasicAuthUsersAuthenticatesEachUser proves every configured user works,
// not just the first one parsed.
func TestBasicAuthUsersAuthenticatesEachUser(t *testing.T) {
	mw, err := BasicAuthUsers("alice:pw1,bob:pw2,carol:pw3", "Gateon")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	h := mw(okHandler())

	for _, u := range []struct{ user, pass string }{
		{"alice", "pw1"}, {"bob", "pw2"}, {"carol", "pw3"},
	} {
		if got := serveBasic(h, u.user, u.pass, true).Code; got != http.StatusOK {
			t.Errorf("%s got %d, want 200", u.user, got)
		}
	}

	// A user's password must not open another user's account.
	if got := serveBasic(h, "alice", "pw2", true).Code; got == http.StatusOK {
		t.Error("alice authenticated with bob's password; the map is being read by " +
			"value rather than by user")
	}
	if got := serveBasic(h, "dave", "pw1", true).Code; got == http.StatusOK {
		t.Error("an unconfigured user authenticated")
	}
}

// TestBasicAuthUsersKeepsColonsInPasswords pins the split.
//
// Splitting on every colon rather than the first would truncate any password
// containing one — silently, and only for the users whose passwords have them.
func TestBasicAuthUsersKeepsColonsInPasswords(t *testing.T) {
	mw, err := BasicAuthUsers("alice:pw:with:colons", "Gateon")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	h := mw(okHandler())

	if got := serveBasic(h, "alice", "pw:with:colons", true).Code; got != http.StatusOK {
		t.Errorf("the full password was refused (got %d); the pair is split on the "+
			"first colon, and everything after it is the password", got)
	}
	if got := serveBasic(h, "alice", "pw", true).Code; got == http.StatusOK {
		t.Error("a truncated password authenticated")
	}
}

// TestConstantTimeCompare covers the helper by contract.
//
// Timing is not asserted — a unit test cannot measure it reliably. What is
// asserted is that it answers correctly, because a constant-time comparison that
// returns the wrong answer is worse than a fast one that does not.
func TestConstantTimeCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"secret", "secret", true},
		{"", "", true},
		{"secret", "secrets", false},
		{"secret", "Secret", false},
		{"secret", "", false},
		{"", "secret", false},
		{"secret", "secre", false},
	} {
		if got := ConstantTimeCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
