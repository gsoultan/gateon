// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUploadScannerSeesEveryTransferEncoding closes a bypass of the base64
// refusal.
//
// Go's NextPart decodes a part whose first Content-Transfer-Encoding is
// quoted-printable and deletes every value of the header, so the refusal
// never saw them. "quoted-printable" followed by "base64" was scanned as
// base64 text while a backend reading the last value saved the decoded file.
func TestUploadScannerSeesEveryTransferEncoding(t *testing.T) {
	// Base64 of an ELF header, unpadded so it is also valid quoted-printable.
	const payload = "f0VMRgIBAQAAAAAAAAAAAAAA"
	body := func(ctes ...string) []byte {
		var b strings.Builder
		b.WriteString("--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\n")
		b.WriteString("Content-Type: image/png\r\n")
		for _, c := range ctes {
			b.WriteString("Content-Transfer-Encoding: " + c + "\r\n")
		}
		b.WriteString("\r\n" + payload + "\r\n--B--\r\n")
		return []byte(b.String())
	}
	cases := []struct {
		name        string
		ctes        []string
		wantBlocked bool
	}{
		{"quoted-printable then base64", []string{"quoted-printable", "base64"}, true},
		{"quoted-printable alone", []string{"quoted-printable"}, true},
		{"base64 alone", []string{"base64"}, true},
		// Controls: what browsers send is still accepted.
		{"no transfer encoding", nil, false},
		{"binary", []string{"binary"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://x/upload", nil)
			res := scanMultipart(r, body(c.ctes...), "B", FileSecurityConfig{}, nil, "", nil, nil)
			if res.blocked != c.wantBlocked {
				t.Errorf("blocked = %v, want %v", res.blocked, c.wantBlocked)
			}
		})
	}
}
