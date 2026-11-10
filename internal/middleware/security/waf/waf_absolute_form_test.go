// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"testing"
)

// TestAbsoluteFormScriptPageIsNotRFI is the regression for absolute-form
// request targets ("GET http://host/index.php", RFC 9112 §3.2.2), which
// net/http accepts and leaves verbatim in r.RequestURI. gwaf recorded that
// target as REQUEST_URI, so it read as an absolute URL ending in ".php" and
// the remote-file-inclusion rule blocked every script page for any client that
// sent absolute form. httptest.NewRequest with a full URL builds exactly that
// request. The attack rows prove the fix did not blind the rule: an inclusion
// URL in a parameter still gets a 403 in both forms.
func TestAbsoluteFormScriptPageIsNotRFI(t *testing.T) {
	cases := []struct {
		target string
		want   int
	}{
		{"/index.php", http.StatusOK},
		{"/app/login.jsp", http.StatusOK},
		{"/default.aspx?id=7", http.StatusOK},
		{"/index.php?page=http://evil.example/shell.php", http.StatusForbidden},
		{"/?file=ftp://evil.example/x.inc%00", http.StatusForbidden},
	}
	for _, c := range cases {
		for _, url := range []string{c.target, "http://app.example" + c.target, "https://app.example:8443" + c.target} {
			if got := fireWAF(t, 1, http.MethodGet, url, "", ""); got != c.want {
				t.Errorf("GET %s: status %d, want %d", url, got, c.want)
			}
		}
	}
}
