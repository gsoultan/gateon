// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// payloads that break out of each of the three contexts challengeID reaches.
//
// The carrier is X-JA4-Fingerprint, not X-Forwarded-For. GetJA4Plus reads that
// header raw and concatenates it into the fingerprint, and GetIPFingerprint
// returns the result before it ever reaches its X-Forwarded-For fallback — so
// the XFF path is effectively unreachable and a test written against it passes
// without exercising anything. Neither header is checked against the trusted
// proxy list on this path, so both are client-controlled.
var powInjectionPayloads = []struct {
	name   string
	header string
	value  string
}{
	{"script string breakout", "X-JA4-Fingerprint", `";alert(document.domain);//`},
	{"html breakout", "X-JA4-Fingerprint", `"></script><script>alert(1)</script>`},
	{"json breakout", "X-JA4-Fingerprint", `","admin":true,"x":"`},
	{"crlf", "X-JA4-Fingerprint", "abc\r\nX-Injected: yes"},
	{"xff fallback", "X-Forwarded-For", `";alert(document.domain);//`},
}

// TestServeChallengeDoesNotReflectFingerprint is the regression test for an XSS
// that bypassed the page's own CSP.
//
// GetJA4Plus reads X-JA4-Fingerprint straight off the request, with no
// trusted-proxy check, and concatenates it into the fingerprint that
// GetIPFingerprint returns. serveChallenge used to interpolate that into
// `const id = "%s";` inside a <script> carrying a valid nonce, so
// `";alert(document.domain);//` closed the literal and ran. The nonce is on the
// very tag containing the injection, which is why the page's own CSP did
// nothing: script-src trusts what it is protecting. The same value also reached
// a response header and a hand-built JSON body.
func TestServeChallengeDoesNotReflectFingerprint(t *testing.T) {
	for _, p := range powInjectionPayloads {
		t.Run(p.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set(p.header, p.value)
			req.RemoteAddr = "203.0.113.9:4444"
			rec := httptest.NewRecorder()

			serveChallenge(rec, req, 3)

			body := rec.Body.String()
			// The marker each payload would produce if it survived. Checking for
			// the payload itself rather than for escaping keeps this honest: any
			// encoding that neutralises it passes, and only a live breakout fails.
			for _, bad := range []string{
				"alert(document.domain)",
				"alert(1)",
				`"admin":true`,
			} {
				if strings.Contains(body, bad) {
					t.Errorf("payload %q survived into the challenge page as %q:\n%s",
						p.value, bad, body)
				}
			}
			if got := rec.Header().Get("X-Injected"); got != "" {
				t.Errorf("header injection succeeded: X-Injected=%q", got)
			}
			if id := rec.Header().Get("X-Gateon-Pow-ID"); strings.ContainsAny(id, "\r\n\"<>") {
				t.Errorf("challenge ID carries unsafe characters: %q", id)
			}
		})
	}
}

// TestChallengeIDIsHexByConstruction pins the shape the three sinks rely on, so
// a future change that puts raw request data back into the ID fails here rather
// than silently reopening the injection.
func TestChallengeIDIsHexByConstruction(t *testing.T) {
	shape := regexp.MustCompile(`^[0-9]+-[0-9a-f]{16}-[0-9a-z]+$`)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-JA4-Fingerprint", `";alert(1);//`)
	rec := httptest.NewRecorder()

	serveChallenge(rec, req, 3)

	id := rec.Header().Get("X-Gateon-Pow-ID")
	if !shape.MatchString(id) {
		t.Errorf("challenge ID %q does not match the expected safe shape %s", id, shape)
	}
}

// TestServeChallengeJSONStaysValid covers the XHR branch, which writes
// challengeID into a hand-built JSON string rather than the HTML page.
func TestServeChallengeJSONStaysValid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-JA4-Fingerprint", `","admin":true,"x":"`)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	serveChallenge(rec, req, 3)

	if body := rec.Body.String(); strings.Contains(body, `"admin":true`) {
		t.Errorf("JSON injection succeeded: %s", body)
	}
}
