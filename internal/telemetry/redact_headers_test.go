// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strings"
	"testing"
)

// A trace keeps that a credential was sent, not what it said. The list used to
// stop at six headers, so an AWS session token, a Google or Azure API key or a
// Vault token was stored as sent -- and, with the trace archive on, kept for
// months and downloadable an hour at a time.
func TestRedactHeaders_RemovesCredentialValues(t *testing.T) {
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token",
		"X-Access-Token", "X-Refresh-Token", "X-Amz-Security-Token", "X-Goog-Api-Key", "Api-Key",
		"Ocp-Apim-Subscription-Key", "X-Functions-Key", "X-Vault-Token", "Private-Token",
		"X-Csrf-Token", "X-Xsrf-Token", "x-amz-security-token", "AUTHORIZATION",
	} {
		got := RedactHeaders(name + ": s3cr3t:with:colons")
		if got != name+": [REDACTED]" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestRedactHeaders_LeavesEverythingElse(t *testing.T) {
	block := strings.Join([]string{
		"Accept: */*",
		"Cookie-Policy: strict", // a name that starts like a credential header is not one
		"X-Api-Key-Id: key-7",
		"Authorization: Bearer abc",
		"Content-Type: application/json",
		"not a header line",
	}, "\n")
	want := strings.Join([]string{
		"Accept: */*",
		"Cookie-Policy: strict",
		"X-Api-Key-Id: key-7",
		"Authorization: [REDACTED]",
		"Content-Type: application/json",
		"not a header line",
	}, "\n")
	if got := RedactHeaders(block); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if RedactHeaders("") != "" {
		t.Fatal("an empty block grew")
	}
}
