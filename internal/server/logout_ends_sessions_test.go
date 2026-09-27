// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sessionCookie is the management plane's session cookie name.
const sessionCookie = "gateon_session"

// signInCookie signs in through POST /v1/login and returns the session cookie
// the gateway set.
func signInCookie(t *testing.T, h http.Handler, username, password string) string {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	rr := serveMgmt(h, http.MethodPost, "/v1/login", body, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("signing in as %s: status %d: %s", username, rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("signing in as %s set no %s cookie", username, sessionCookie)
	return ""
}

// serveMgmt sends one request to the management handler, carrying cookie as
// the session cookie when it is not empty.
func serveMgmt(h http.Handler, method, path, body, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://gateway.example"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5555"
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestSignOutEndsTheSessionItSignsOut is the handler-level regression test for
// a sign-out that ended nothing.
//
// Root cause: POST /v1/logout cleared the browser's cookie and wrote an audit
// entry, and the token the cookie held was a bearer token none of whose
// binding inputs had changed -- so a copy of the cookie, replayed, went on
// working until it expired, up to eight hours later.
func TestSignOutEndsTheSessionItSignsOut(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	laptop := signInCookie(t, h, "root", "correct-horse")
	phone := signInCookie(t, h, "root", "correct-horse")
	if rr := serveMgmt(h, http.MethodGet, "/v1/me", "", laptop); rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/me with a fresh session: status %d: %s", rr.Code, rr.Body.String())
	}

	out := serveMgmt(h, http.MethodPost, "/v1/logout", "", laptop)
	if out.Code != http.StatusOK {
		t.Fatalf("POST /v1/logout: status %d: %s", out.Code, out.Body.String())
	}
	if !clearsSessionCookie(out) {
		t.Errorf("POST /v1/logout did not clear the session cookie: %v", out.Header().Values("Set-Cookie"))
	}

	for name, cookie := range map[string]string{
		"the signed-out cookie, replayed":         laptop,
		"the account's session on another device": phone,
	} {
		if rr := serveMgmt(h, http.MethodGet, "/v1/me", "", cookie); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: GET /v1/me = %d after signing out, want 401", name, rr.Code)
		}
	}
}

// TestASecondSignOutChangesNothing: the replayed cookie of a session already
// signed out is refused like any other ended session, and signing in again
// still works afterwards.
func TestASecondSignOutChangesNothing(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")
	if rr := serveMgmt(h, http.MethodPost, "/v1/logout", "", cookie); rr.Code != http.StatusOK {
		t.Fatalf("first sign-out: status %d: %s", rr.Code, rr.Body.String())
	}
	if rr := serveMgmt(h, http.MethodPost, "/v1/logout", "", cookie); rr.Code != http.StatusUnauthorized {
		t.Errorf("second sign-out with the ended session: status %d, want 401: %s", rr.Code, rr.Body.String())
	}
	fresh := signInCookie(t, h, "root", "correct-horse")
	if rr := serveMgmt(h, http.MethodGet, "/v1/me", "", fresh); rr.Code != http.StatusOK {
		t.Errorf("a session begun after two sign-outs: GET /v1/me = %d, want 200", rr.Code)
	}
}

func clearsSessionCookie(rr *httptest.ResponseRecorder) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}
