// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// failingBody yields n bytes and then fails, which is what a client that
// disconnects mid-upload looks like from the server's side.
type failingBody struct {
	data []byte
	pos  int
}

func (f *failingBody) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, errors.New("connection reset by peer")
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

func (f *failingBody) Close() error { return nil }

// TestScanRequestSourcesRestoresBytesItConsumedOnReadError pins the bytes, not
// the error.
//
// scanRequestSources peeks the body to scan it and puts it back for the
// upstream. On a read error it returned early without putting anything back --
// but io.ReadAll returns the bytes it managed to read alongside the error, so
// those bytes were consumed from the client's stream and then dropped. The
// upstream received the request with a hole at the front and no indication
// anything was missing.
//
// A read error usually means the client is gone, which is why this never
// surfaced. "Usually" is not "always", and silently truncating a body on the
// request path is the wrong failure mode either way.
func TestScanRequestSourcesRestoresBytesItConsumedOnReadError(t *testing.T) {
	const prefix = "POSTED-BODY-PREFIX-THAT-MUST-SURVIVE"

	r := httptest.NewRequest(http.MethodPost, "http://example.com/upload", nil)
	r.Body = &failingBody{data: []byte(prefix)}

	scanRequestSources(r, false, func(string, string) bool { return false })

	got, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(got), prefix) {
		t.Errorf("upstream would receive %q, missing the %d bytes the scanner "+
			"consumed before the read failed; the body is silently truncated",
			string(got), len(prefix))
	}
}

// TestEntropyRestoresBytesItConsumedOnReadError covers the second of four
// sites that had this shape. Entropy forwards the request whatever it finds,
// so dropping the consumed bytes truncates the body for the upstream.
func TestEntropyRestoresBytesItConsumedOnReadError(t *testing.T) {
	const prefix = "ENTROPY-BODY-PREFIX-THAT-MUST-SURVIVE"

	var upstream string
	h := Entropy(4.5, "entropy-restore")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstream = string(b)
	}))

	r := httptest.NewRequest(http.MethodPost, "http://example.com/u", nil)
	r.Body = &failingBody{data: []byte(prefix)}
	r.RemoteAddr = "203.0.113.9:1234"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if !strings.Contains(upstream, prefix) {
		t.Errorf("upstream received %q, missing the %d bytes Entropy consumed "+
			"before the read failed", upstream, len(prefix))
	}
}
