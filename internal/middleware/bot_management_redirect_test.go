// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSafeRedirectTarget covers the two ways the challenge redirect used to
// leave the origin: an absolute URL, and the protocol-relative forms that slip
// past a plain "starts with /" test.
func TestSafeRedirectTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty falls back", "", "/"},
		{"plain path", "/dashboard", "/dashboard"},
		{"path with query", "/search?q=1&x=2", "/search?q=1&x=2"},
		{"absolute http", "http://evil.com/x", "/"},
		{"absolute https", "https://evil.com/x", "/"},
		{"protocol relative", "//evil.com/x", "/"},
		{"backslash protocol relative", `/\evil.com/x`, "/"},
		{"scheme relative with creds", "https://user:pw@evil.com", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"opaque mailto", "mailto:a@b.c", "/"},
		{"relative without slash", "evil.com/x", "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeRedirectTarget(tc.in); got != tc.want {
				t.Errorf("safeRedirectTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestServeJSChallengeEscapesRequestURI proves the challenge page cannot be
// broken out of by a crafted request path. Before the escape, a path of
// `/"><base href="https://evil.com/">` closed the hidden input's value
// attribute and injected a <base> tag, which repoints every relative URL on the
// page — the form action and the seed fetch included — at the attacker. The CSP
// on this response blocks injected inline script but says nothing about <base>,
// so the escaping is what actually holds here.
func TestServeJSChallengeEscapesRequestURI(t *testing.T) {
	const marker = `"><base href="https://evil.com/">`

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set RequestURI directly: url.Parse would reject or normalise the raw
	// quote, and what matters is what an attacker can put on the wire.
	req.URL.Path = marker
	rec := httptest.NewRecorder()

	serveJSChallenge(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<base") {
		t.Errorf("challenge page contains an injected <base> tag:\n%s", body)
	}
	if strings.Contains(body, `value=""><`) {
		t.Errorf("attacker closed the value attribute:\n%s", body)
	}
	if !strings.Contains(body, "&lt;base") && strings.Contains(body, "base") {
		t.Errorf("expected the injected markup to be escaped, got:\n%s", body)
	}
}

// challengeToken mints a token the middleware will accept, so the test can
// reach the redirect that only runs after a challenge is solved.
func challengeToken(t *testing.T, secret, payload, ua, ip string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, payload)
	_, _ = io.WriteString(mac, ua)
	_, _ = io.WriteString(mac, ip)
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// TestChallengeSubmissionCannotRedirectOffOrigin is the regression test for the
// open redirect. The "redirect" form value is whatever the challenge page put
// in the client's hands, so it is attacker-controlled by the time it comes
// back; before the fix it went to http.Redirect verbatim and a solved challenge
// forwarded the victim to any host the attacker named. That the victim arrives
// having just passed a security check is what makes it worth phishing with.
func TestChallengeSubmissionCannotRedirectOffOrigin(t *testing.T) {
	const (
		secret = "test-secret"
		ua     = "Mozilla/5.0 (test)"
	)

	for _, target := range []string{
		"https://evil.com/login",
		"//evil.com/login",
		`/\evil.com/login`,
	} {
		t.Run(target, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			h := BotManagement(BotManagementConfig{
				Enabled:           true,
				EnableJSChallenge: true,
				SecretKey:         secret,
			})(next)

			form := url.Values{}
			form.Set("redirect", target)

			req := httptest.NewRequest(http.MethodPost, "/_gateon/challenge",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", ua)
			req.RemoteAddr = "203.0.113.7:1234"

			// The payload is parsed as a Unix timestamp and rejected if it is
			// older than the challenge window, so it has to be a real one.
			clientIP := req.RemoteAddr[:strings.LastIndex(req.RemoteAddr, ":")]
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			form.Set("token", challengeToken(t, secret, ts, ua, clientIP))
			req.Body = io.NopCloser(strings.NewReader(form.Encode()))
			req.ContentLength = int64(len(form.Encode()))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			// Assert the redirect actually happened before asserting where it
			// went. Without this the test passes for the wrong reason: if the
			// token stops verifying, the middleware never reaches
			// http.Redirect, Location is empty, and an "is not evil.com" check
			// is satisfied by a request that was simply rejected.
			if rec.Code != http.StatusFound {
				t.Fatalf("expected 302 after a solved challenge, got %d: %s",
					rec.Code, rec.Body.String())
			}
			loc := rec.Header().Get("Location")
			if loc == "" {
				t.Fatal("expected a Location header after a solved challenge")
			}
			if strings.Contains(loc, "evil.com") {
				t.Errorf("open redirect: Location = %q for redirect=%q", loc, target)
			}
		})
	}
}

// TestServeJSChallengeKeepsBenignPath guards the escape against over-reach: a
// normal path still has to survive into the form so the user lands back where
// they started once the challenge is solved.
func TestServeJSChallengeKeepsBenignPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app/page?tab=2", nil)
	rec := httptest.NewRecorder()

	serveJSChallenge(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `value="/app/page?tab=2"`) {
		t.Errorf("benign redirect target did not survive into the form:\n%s", body)
	}
}
