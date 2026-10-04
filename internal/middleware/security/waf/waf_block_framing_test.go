// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestDLPBlockSendsItsOwnFraming is T39. A refused response used to go out
// under the origin's headers: the origin's Content-Length (the length of the
// body that leaked) framing a 47-byte refusal. A client reading it hit an
// unexpected EOF -- Python's IncompleteRead -- and an HTTP/1.1 connection was
// left waiting for bytes that never came. The refusal is a different body, so
// it carries its own length, and nothing that described the origin's body.
func TestDLPBlockSendsItsOwnFraming(t *testing.T) {
	body := `{"card":"` + leakVisa + `","padding":"` + strings.Repeat("x", 64) + `"}`
	srv := httptest.NewServer(dlpHandler(t, dlpBlock, "application/json", body, false))
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/dump", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the refusal failed (%v) after %d bytes under Content-Length %d; "+
			"the refusal went out under the origin's framing", err, len(got), resp.ContentLength)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if resp.ContentLength != int64(len(got)) {
		t.Errorf("Content-Length %d but the body is %d bytes", resp.ContentLength, len(got))
	}
	if strings.Contains(string(got), leakVisa) {
		t.Error("the card reached the client")
	}
}

// TestDLPBlockDropsTheOriginsEncoding covers the compressed origin. The refusal
// is plain text; leaving Content-Encoding: gzip on it makes every client fail
// to decode the 403 instead of reading it.
func TestDLPBlockDropsTheOriginsEncoding(t *testing.T) {
	body := `{"card":"` + leakVisa + `"}`
	handler := dlpHandler(t, dlpBlock, "application/json", body, true)

	req := httptest.NewRequest(http.MethodGet, "/api/dump", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("refusal sent with Content-Encoding %q but its body is plain text", enc)
	}
	if cl := rec.Header().Get("Content-Length"); cl != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length is %q but the refusal is %d bytes", cl, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("refusal labelled %q, want text/plain", ct)
	}
}
