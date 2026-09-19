// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// webshellPayload trips the built-in php_webshell rule (critical), so a part
// that carries it and still reaches the backend was never scanned.
const webshellPayload = `<?php eval($_POST["c"]); ?>`

// rawMultipartRequest builds a POST from a hand-written multipart body, so the
// tests can produce the shapes mime/multipart.Writer refuses to emit.
func rawMultipartRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", `multipart/form-data; boundary=BOUNDARY`)
	return req
}

// TestFileSecurity_ParserDifferentialsFailClosed is the regression test for
// three fail-open paths in the upload scanner. Each body is one that Go's
// mime/multipart parser handles differently from the lenient parsers behind
// the gateway (PHP's rfc1867, Django, busboy), and in each case the scanner
// used to report the body clean and forward it intact -- the webshell reached
// the backend without a single signature being evaluated.
func TestFileSecurity_ParserDifferentialsFailClosed(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			// mime.ParseMediaType rejects a parameter repeated with a different
			// value, so Part.FileName() returned "" and the part was skipped as an
			// ordinary form field. PHP, Django and busboy keep the last filename
			// and save shell.php.
			name: "duplicate filename parameter",
			body: "--BOUNDARY\r\n" +
				"Content-Disposition: form-data; name=\"f\"; filename=\"notes.txt\"; filename=\"shell.php\"\r\n" +
				"Content-Type: text/plain\r\n\r\n" +
				webshellPayload + "\r\n" +
				"--BOUNDARY--\r\n",
			wantStatus: http.StatusForbidden,
		},
		{
			// No closing delimiter: Part.Read hands back the content together
			// with io.ErrUnexpectedEOF, and the read-error path allowed the part.
			name: "truncated body without closing boundary",
			body: "--BOUNDARY\r\n" +
				"Content-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\n" +
				webshellPayload,
			wantStatus: http.StatusBadRequest,
		},
		{
			// A header line without a colon makes NextPart fail; the loop broke
			// out and reported the body clean, forwarding the unscanned part
			// that follows.
			name: "malformed part header",
			body: "--BOUNDARY\r\n" +
				"Content-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n" +
				"--BOUNDARY\r\n" +
				"this-line-has-no-colon\r\n" +
				"Content-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\n" +
				webshellPayload + "\r\n" +
				"--BOUNDARY--\r\n",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := FileSecurity(FileSecurityConfig{EnableSignatureScan: true})
			forwarded := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, rawMultipartRequest(tc.body))

			if forwarded {
				t.Errorf("an upload the scanner could not inspect was forwarded to the backend")
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}
