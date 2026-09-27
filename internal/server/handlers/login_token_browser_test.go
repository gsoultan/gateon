// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const issuedToken = "v4.local.ISSUED-SESSION-TOKEN"

// signInAPI completes every sign-in, in one step or two, with issuedToken --
// what the service does for a correct password or a correct second factor.
type signInAPI struct {
	GlobalAndAuthAPI
}

func (signInAPI) Login(context.Context, *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	return &gateonv1.LoginResponse{Token: issuedToken, User: &gateonv1.User{Id: "u1", Username: "alice"}}, nil
}

func (signInAPI) Verify2FA(context.Context, *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error) {
	return &gateonv1.Verify2FAResponse{Success: true, Token: issuedToken, User: &gateonv1.User{Id: "u1"}}, nil
}

// signIn posts an unauthenticated sign-in step. fetchMode is what a browser
// would put in Sec-Fetch-Mode; "" is a client that is not a browser.
func signIn(t *testing.T, path, body, fetchMode string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, signInAPI{}, &Deps{})
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if fetchMode != "" {
		req.Header.Set("Sec-Fetch-Mode", fetchMode)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, authWaived(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", path, rr.Code, rr.Body.String())
	}
	return rr
}

func sessionCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == "gateon_session" {
			return c
		}
	}
	return nil
}

func bodyToken(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	return got.Token
}

var signInSteps = []struct{ name, path, body string }{
	{"password", "/v1/login", `{"username":"alice","password":"pw"}`},
	{"second factor", "/v1/auth/2fa/verify", `{"id":"u1","code":"123456"}`},
}

// TestSignInGivesABrowserTheSessionOnlyAsTheCookie: both sign-in steps set the
// HttpOnly cookie and also wrote the token into the body, where any script in
// the page -- including script that wrapped fetch before the form was
// submitted -- could read it and carry it off as a bearer credential that
// outlives the tab. A browser sends Sec-Fetch-Mode on every request and page
// script can neither forge nor strip it.
func TestSignInGivesABrowserTheSessionOnlyAsTheCookie(t *testing.T) {
	for _, step := range signInSteps {
		for _, mode := range []string{"cors", "same-origin", "navigate"} {
			t.Run(step.name+"/"+mode, func(t *testing.T) {
				rr := signIn(t, step.path, step.body, mode)

				c := sessionCookie(t, rr)
				if c == nil || c.Value != issuedToken || !c.HttpOnly {
					t.Fatalf("the session cookie was not set as an HttpOnly cookie carrying the session: %+v", c)
				}
				if strings.Contains(rr.Body.String(), issuedToken) {
					t.Errorf("a browser was handed the session token in the body: %s", rr.Body.String())
				}
			})
		}
	}
}

// TestSignInStillGivesAnAPIClientTheToken pins what API clients depend on: a
// program with no cookie jar to speak of reads the session from the body.
func TestSignInStillGivesAnAPIClientTheToken(t *testing.T) {
	for _, step := range signInSteps {
		t.Run(step.name, func(t *testing.T) {
			rr := signIn(t, step.path, step.body, "")

			if got := bodyToken(t, rr); got != issuedToken {
				t.Errorf("token in the body = %q, want the session token", got)
			}
		})
	}
}
