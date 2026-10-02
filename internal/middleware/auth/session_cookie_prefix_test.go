// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// On a secure request the session cookie is named __Host-gateon_session
// (ADR 0041). A browser keeps a __Host- cookie only if it is Secure, has
// Path=/ and no Domain, so a sibling subdomain or a plaintext response on the
// same host can neither plant one nor overwrite it. The old name is read for
// one release so that sessions signed in before the upgrade survive it.

func secureRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestSecureSessionCookieIsHostPrefixed(t *testing.T) {
	r := secureRequest(http.MethodPost, "/v1/login")
	c := namedCookieFrom(t, r, func(w http.ResponseWriter, r *http.Request) {
		SetSessionCookie(w, r, "tok", 3600)
	}, "__Host-gateon_session")

	// The prefix is a promise the browser enforces only if these hold; a
	// cookie that breaks one is silently dropped and nobody can sign in.
	if !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Errorf("__Host- cookie with Secure=%v Path=%q Domain=%q; a browser drops it unless Secure, Path=/ and no Domain",
			c.Secure, c.Path, c.Domain)
	}
	if c.Value != "tok" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %+v, want the token, HttpOnly and SameSite=Strict", c)
	}
}

func TestPlainHTTPSessionCookieKeepsItsName(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/login", nil)
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, r, "tok", 3600)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "gateon_session" || cookies[0].Value != "tok" {
		t.Errorf("plain-HTTP sign-in set %v, want exactly gateon_session=tok: a browser refuses a __Host- cookie "+
			"that is not Secure, so on plain HTTP the prefix would make sign-in impossible", cookies)
	}
}

// TestSecureSignInExpiresTheOldName: a browser carrying a session from before
// the upgrade signs in again and must not be left holding two.
func TestSecureSignInExpiresTheOldName(t *testing.T) {
	r := secureRequest(http.MethodPost, "/v1/login")
	old := namedCookieFrom(t, r, func(w http.ResponseWriter, r *http.Request) {
		SetSessionCookie(w, r, "tok", 3600)
	}, "gateon_session")
	if old.MaxAge >= 0 || old.Value != "" || !old.Secure {
		t.Errorf("old-name cookie %+v, want it expired, empty and Secure (a Secure cookie is cleared only by a Secure one)", old)
	}
}

func TestSecureClearClearsBothNames(t *testing.T) {
	r := secureRequest(http.MethodPost, "/v1/logout")
	for _, name := range []string{"__Host-gateon_session", "gateon_session"} {
		c := namedCookieFrom(t, r, ClearSessionCookie, name)
		if c.MaxAge >= 0 || !c.Secure {
			t.Errorf("sign-out set %s with MaxAge=%d Secure=%v, want it expired and Secure", name, c.MaxAge, c.Secure)
		}
	}
}

func TestExtractTokenReadsTheSessionUnderEitherName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cookies map[string]string
		want    string
	}{
		{"prefixed", map[string]string{"__Host-gateon_session": "new"}, "new"},
		{"signed in before the upgrade", map[string]string{"gateon_session": "old"}, "old"},
		{"both: the prefixed one wins", map[string]string{"gateon_session": "old", "__Host-gateon_session": "new"}, "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := secureRequest(http.MethodGet, "/v1/me")
			for n, v := range tc.cookies {
				r.AddCookie(&http.Cookie{Name: n, Value: v})
			}
			if got := ExtractToken(r); got != tc.want {
				t.Errorf("ExtractToken = %q, want %q", got, tc.want)
			}
		})
	}
}

// BenchmarkStripSessionCookie is the per-request cost the proxy pays, with no
// session cookie (every app request) and with one (an admin's browser).
func BenchmarkStripSessionCookie(b *testing.B) {
	for _, bc := range []struct{ name, line string }{
		{"absent", "a=1; b=2; theme=dark; _ga=GA1.2.3; gateon_session_r1=oidc"},
		{"present", "a=1; gateon_session=v4.local.ADMIN; b=2; theme=dark"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			lines := []string{bc.line}
			h := http.Header{}
			b.ReportAllocs()
			for b.Loop() {
				lines[0] = bc.line
				h["Cookie"] = lines
				StripSessionCookie(h)
			}
		})
	}
}

func TestStripSessionCookie(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string // nil: no Cookie header left
	}{
		{"no session", []string{"a=1; b=2"}, []string{"a=1; b=2"}},
		{"session between others", []string{"a=1; gateon_session=x; b=2"}, []string{"a=1; b=2"}},
		{"both names", []string{"__Host-gateon_session=y;a=1;gateon_session=x"}, []string{"a=1"}},
		{"only the session", []string{"gateon_session=x"}, nil},
		{"one of several lines", []string{"a=1", "gateon_session=x", "b=2"}, []string{"a=1", "b=2"}},
		{"a route's OIDC cookie is the app's", []string{"gateon_session_r1=o; gateon_sessionx=z"},
			[]string{"gateon_session_r1=o; gateon_sessionx=z"}},
		{"spacing around the name", []string{"a=1;  gateon_session =x ; b=2"}, []string{"a=1; b=2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Cookie": append([]string(nil), tc.in...)}
			StripSessionCookie(h)
			got, present := h["Cookie"]
			if tc.want == nil {
				if present {
					t.Errorf("Cookie = %q, want the header removed", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Cookie = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Cookie = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
