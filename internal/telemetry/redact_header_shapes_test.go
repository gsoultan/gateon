// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strings"
	"testing"
)

// shapeJWT is a JSON Web Token: what AWS ALB's X-Amzn-Oidc-Data carries, and
// what an identity-aware proxy puts in its assertion header.
const shapeJWT = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJhZGEiLCJlbWFpbCI6ImFkYUBleGFtcGxlLmNvbSJ9.c2lnbmF0dXJlLWJ5dGVz"

// TestRedactHeaders_MasksCredentialShapesUnderAnyName: header redaction was by
// name only, so a credential under a header named for something else was
// stored as sent in every recorded trace, every threat and the generic
// webhook's requestHeaders (review 3, F4), contradicting ADR 0060's "by name or
// shape". The same values in a query string were masked. The rest of a
// structured value stays readable.
func TestRedactHeaders_MasksCredentialShapesUnderAnyName(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"X-Id-Assertion: " + shapeJWT, "X-Id-Assertion: [REDACTED]"},
		{"X-Amzn-Oidc-Data: " + shapeJWT, "X-Amzn-Oidc-Data: [REDACTED]"},
		{"X-Upstream: gateon_tok_4f9a2c7e1b3d5f60", "X-Upstream: gateon_tok_[REDACTED]"},
		{"Forwarded: for=198.51.100.7;proto=https;by=" + shapeJWT,
			"Forwarded: for=198.51.100.7;proto=https;by=[REDACTED]"},
		{"X-Client-Data: Bearer 3q2+7wAAAAAAAAAAAAAA", "X-Client-Data: Bearer [REDACTED]"},
		{"X-Legacy-Login: Basic YWRhOmNvcnJlY3QtaG9yc2U=", "X-Legacy-Login: Basic [REDACTED]"},
		{"X-Assertion: v4.public.eyJzdWIiOiJhZGEifQAbCdEf", "X-Assertion: v4.public.[REDACTED]"},
		{"X-Proxy-Hint: Bearer%203q2-7wAAAAAAAAAAAAAA", "X-Proxy-Hint: [REDACTED]"},
		{"X-Trace-Context: user=ada, jwt=" + shapeJWT + ", hop=2", "X-Trace-Context: user=ada, jwt=[REDACTED], hop=2"},
	} {
		if got := RedactHeaders(tc.line); got != tc.want {
			t.Errorf("RedactHeaders(%q)\n got %q\nwant %q", tc.line, got, tc.want)
		}
	}
}

// TestRedactHeaders_LeavesOrdinaryValuesAlone is the other half: an ordinary
// browser request keeps every header but its session cookie, and a challenge
// that names the Bearer scheme is not a credential.
func TestRedactHeaders_LeavesOrdinaryValuesAlone(t *testing.T) {
	want := strings.Replace(browserRequestHeaders,
		"Cookie: _ga=GA1.1.1234567890.1700000000; sid=7f3c2a9e4b1d4c8f9a0b", "Cookie: [REDACTED]", 1)
	if got := RedactHeaders(browserRequestHeaders); got != want {
		t.Errorf("an ordinary request's headers changed:\n got %q\nwant %q", got, want)
	}
	for _, line := range []string{
		`WWW-Authenticate: Bearer error_description="the access token expired", realm="api"`,
		`Proxy-Authenticate: Basic realm="corp proxy"`,
		"X-Request-Id: eyJ-not-a-token",
		"X-Note: the bearer of this message",
		"Content-Disposition: attachment; filename=\"basic tutorial.pdf\"",
	} {
		if got := RedactHeaders(line); got != line {
			t.Errorf("RedactHeaders(%q) = %q, want it unchanged", line, got)
		}
	}
}
