// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ADR 0051. The base handler withholds management credentials before any
// route middleware runs; these pin the second line, in the two middlewares
// that send a request's credentials to a server the operator chose: if a
// management credential ever reaches them, they do not pass it on.

const (
	mgmtSession   = "v4.local.MGMT-SESSION"
	mgmtScrape    = "gateon_tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	appPaseto     = "v4.local.APP-OWN-TOKEN"
	appOpaque     = "app-opaque-token"
	browserCookie = "other=1; gateon_session=" + mgmtSession + "; __Host-gateon_session=" + mgmtSession +
		"; gateon_session_r1=oidc; last=2"
	appCookieLine = "other=1; gateon_session_r1=oidc; last=2"
)

// mgmtVerifier accepts mgmtSession and nothing else, as the management
// plane's verifier accepts its own sessions and not an app's PASETO token.
type mgmtVerifier struct{}

func (mgmtVerifier) VerifyToken(token string) (any, error) {
	if token == mgmtSession {
		return struct{}{}, nil
	}
	return nil, errors.New("not a management session")
}

// outbound records what a server the operator chose was sent.
type outbound struct {
	mu      sync.Mutex
	headers []http.Header
	tokens  []string
}

func (o *outbound) server(t *testing.T, answer func(token string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		o.mu.Lock()
		o.headers = append(o.headers, r.Header.Clone())
		if tok := r.PostForm.Get("token"); tok != "" {
			o.tokens = append(o.tokens, tok)
		}
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, answer(r.PostForm.Get("token")))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (o *outbound) take() ([]http.Header, []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h, tk := o.headers, o.tokens
	o.headers, o.tokens = nil, nil
	return h, tk
}

func okBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// TestForwardAuthDoesNotForwardAManagementCredential: the auth server gets
// the app's cookies and the app's own credentials, and never the session
// cookie (either name), a session the management plane accepts, or a scrape
// token.
func TestForwardAuthDoesNotForwardAManagementCredential(t *testing.T) {
	var seen outbound
	srv := seen.server(t, func(string) string { return "" })
	mw, err := ForwardAuth(ForwardAuthConfig{Address: srv.URL + "/verify", ManagementSessions: mgmtVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(okBackend())
	for _, tc := range []struct {
		name, authz, wantAuthz string
	}{
		{"session cookie and an app's PASETO token", "Bearer " + appPaseto, "Bearer " + appPaseto},
		{"session as a bearer", "Bearer " + mgmtSession, ""},
		{"scrape token", "Bearer " + mgmtScrape, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/app", nil)
			req.Header.Set("Cookie", browserCookie)
			req.Header.Set("Authorization", tc.authz)
			h.ServeHTTP(httptest.NewRecorder(), req)
			headers, _ := seen.take()
			if len(headers) != 1 {
				t.Fatalf("auth server was called %d times, want once", len(headers))
			}
			if got := strings.Join(headers[0].Values("Cookie"), " | "); got != appCookieLine {
				t.Errorf("auth server saw Cookie %q, want %q", got, appCookieLine)
			}
			if got := headers[0].Get("Authorization"); got != tc.wantAuthz {
				t.Errorf("auth server saw Authorization %q, want %q", got, tc.wantAuthz)
			}
		})
	}
}

// TestIntrospectionDoesNotPostAManagementCredential: the session cookie used
// to be the first token introspection read, so the administrator's browser had
// its session posted as token= and its app token ignored. The app's token is
// what is introspected; a management credential is never posted.
func TestIntrospectionDoesNotPostAManagementCredential(t *testing.T) {
	var seen outbound
	srv := seen.server(t, func(tok string) string {
		if tok == appOpaque {
			return `{"active":true,"sub":"app-user"}`
		}
		return `{"active":false}`
	})
	v, err := NewOAuth2IntrospectionValidator(OAuth2IntrospectionConfig{
		IntrospectionURL: srv.URL, ClientID: "gw", ClientSecret: "s3cret", ManagementSessions: mgmtVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := v.Handler(okBackend())
	for _, tc := range []struct {
		name, cookie, authz string
		want                int
		wantPosted          []string
	}{
		{"admin browser with the app's token", browserCookie, "Bearer " + appOpaque, http.StatusOK, []string{appOpaque}},
		{"admin browser with no app token", browserCookie, "", http.StatusUnauthorized, nil},
		{"session as a bearer", "", "Bearer " + mgmtSession, http.StatusUnauthorized, nil},
		{"scrape token", "", "Bearer " + mgmtScrape, http.StatusUnauthorized, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/app", nil)
			if tc.cookie != "" {
				req.Header.Set("Cookie", tc.cookie)
			}
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			_, posted := seen.take()
			if rr.Code != tc.want {
				t.Errorf("status %d, want %d", rr.Code, tc.want)
			}
			if strings.Join(posted, ",") != strings.Join(tc.wantPosted, ",") {
				t.Errorf("introspection was posted %q, want %q", posted, tc.wantPosted)
			}
		})
	}
}

// TestWithholdManagementCredentialsChecksEveryAuthorizationValue: a request
// may carry Authorization more than once; reading only the first let a second
// value through.
func TestWithholdManagementCredentialsChecksEveryAuthorizationValue(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer " + appPaseto, "Bearer " + mgmtSession, "bearer " + mgmtScrape, "Basic YTpi"}}
	WithholdManagementCredentials(h, mgmtVerifier{})
	if got, want := strings.Join(h.Values("Authorization"), " | "), "Bearer "+appPaseto+" | Basic YTpi"; got != want {
		t.Errorf("Authorization after withholding = %q, want %q", got, want)
	}
	only := http.Header{"Authorization": {"Bearer " + mgmtSession}}
	WithholdManagementCredentials(only, mgmtVerifier{})
	if _, ok := only["Authorization"]; ok {
		t.Errorf("an Authorization header holding only a session was left as %q, want it removed", only["Authorization"])
	}
}

// TestWithholdingAllocatesNothingWithoutAManagementCredential pins the cost on
// the request path: one scan, no allocation, no verification.
func TestWithholdingAllocatesNothingWithoutAManagementCredential(t *testing.T) {
	asked := 0
	v := countingVerifier{asked: &asked}
	h := http.Header{
		"Cookie":        {"a=1; theme=dark; gateon_session_r1=oidc; _ga=GA1.2.3"},
		"Authorization": {"Bearer eyJhbGciOi.x.y"},
	}
	if n := testing.AllocsPerRun(100, func() {
		if MayCarryManagementCredential(h) {
			t.Fatal("a request with no management credential was taken for one carrying one")
		}
		WithholdManagementCredentials(h, v)
	}); n != 0 {
		t.Errorf("withholding from a request with no management credential allocated %.0f times, want 0", n)
	}
	if asked != 0 {
		t.Errorf("the verifier was asked %d times about a JWT, want 0", asked)
	}
}

type countingVerifier struct{ asked *int }

func (c countingVerifier) VerifyToken(string) (any, error) {
	*c.asked++
	return nil, errors.New("no")
}

// TestMayCarryManagementCredentialMissesNone: the base handler withholds only
// when this says there may be something to withhold, so a false negative is a
// credential passed to the route's middlewares.
func TestMayCarryManagementCredentialMissesNone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"session cookie", http.Header{"Cookie": {"a=1; gateon_session=x"}}, true},
		{"session cookie, secure name", http.Header{"Cookie": {"__Host-gateon_session=x"}}, true},
		{"session cookie on a second line", http.Header{"Cookie": {"a=1", "gateon_session=x"}}, true},
		{"session bearer", http.Header{"Authorization": {"Bearer " + mgmtSession}}, true},
		{"an app's PASETO bearer, which only the verifier can tell apart", http.Header{"Authorization": {"Bearer " + appPaseto}}, true},
		{"scrape token", http.Header{"Authorization": {"Bearer " + mgmtScrape}}, true},
		{"scrape token as a second value", http.Header{"Authorization": {"Basic YTpi", "bearer " + mgmtScrape}}, true},
		{"a route's OIDC cookie", http.Header{"Cookie": {"gateon_session_r1=oidc"}}, false},
		{"a JWT", http.Header{"Authorization": {"Bearer eyJhbGciOi.x.y"}}, false},
		{"nothing", http.Header{}, false},
	} {
		if got := MayCarryManagementCredential(tc.header); got != tc.want {
			t.Errorf("%s: MayCarryManagementCredential = %v, want %v", tc.name, got, tc.want)
		}
	}
}
