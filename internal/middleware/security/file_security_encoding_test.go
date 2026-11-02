// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// pngThenELF is a PNG head with an ELF image behind it: the embedded-executable
// scan refuses it whenever it can see the bytes.
var pngThenELF = append(
	[]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"),
	append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 64)...)...)

// TestFileSecurity_RefusesShapesTheScannerCannotSee covers two encodings the
// scanner never decoded, so the bytes a backend saved were not the bytes that
// were scanned.
//
// A form-data part with no filename and a multipart/mixed body was skipped as
// an ordinary field, while RFC 2388 parsers (commons-fileupload) unpack the
// inner parts as files. And Go's multipart reader decodes only
// quoted-printable, so a part with Content-Transfer-Encoding: base64 was
// scanned as base64 text while a backend that honours the header saved the
// decoded executable. Browsers produce neither shape -- RFC 7578 deprecates
// multipart/mixed and forbids Content-Transfer-Encoding -- so both are refused
// rather than decoded: no recursion and no second buffer to bound on a
// two-core host.
func TestFileSecurity_RefusesShapesTheScannerCannotSee(t *testing.T) {
	inner := "--inner\r\n" +
		"Content-Disposition: file; filename=\"a.exe\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		string(pngThenELF) + "\r\n" +
		"--inner--\r\n"
	cases := map[string]string{
		"nested multipart/mixed": "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"files\"\r\n" +
			"Content-Type: multipart/mixed; boundary=inner\r\n\r\n" +
			inner + "\r\n" +
			"--BOUNDARY--\r\n",
		"nested multipart, mixed case": "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"files\"\r\n" +
			"Content-Type: Multipart/Mixed; boundary=inner\r\n\r\n" +
			inner + "\r\n" +
			"--BOUNDARY--\r\n",
		"base64 transfer encoding": "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\n" +
			"Content-Type: image/png\r\n" +
			"Content-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString(pngThenELF) + "\r\n" +
			"--BOUNDARY--\r\n",
		"base64 on a field": "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"f\"\r\n" +
			"Content-Transfer-Encoding: BASE64\r\n\r\n" +
			base64.StdEncoding.EncodeToString(pngThenELF) + "\r\n" +
			"--BOUNDARY--\r\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			forwarded, code := serveFileSecurity(rawMultipartRequest(body))
			if forwarded {
				t.Errorf("an upload the scanner could not read as the backend does was forwarded (status %d)", code)
			}
			if code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", code, http.StatusBadRequest)
			}
		})
	}
}

// TestFileSecurity_StillPassesPlainTransferEncodings keeps the refusal to the
// encodings that change the bytes: 7bit, 8bit and binary are identity
// encodings some clients still label parts with.
func TestFileSecurity_StillPassesPlainTransferEncodings(t *testing.T) {
	for _, cte := range []string{"binary", "8bit", "7BIT"} {
		body := "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Transfer-Encoding: " + cte + "\r\n\r\n" +
			"hello\r\n" +
			"--BOUNDARY--\r\n"
		if forwarded, code := serveFileSecurity(rawMultipartRequest(body)); !forwarded {
			t.Errorf("Content-Transfer-Encoding %s: refused with %d, want forwarded", cte, code)
		}
	}
}

func serveFileSecurity(req *http.Request) (bool, int) {
	mw := FileSecurity(FileSecurityConfig{EnableSignatureScan: true})
	forwarded := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return forwarded, rec.Code
}
