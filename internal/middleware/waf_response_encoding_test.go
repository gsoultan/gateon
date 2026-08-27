// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// leakedSecret is an AWS access key id in the shape rule 1130003 matches. It is
// syntactically valid and has never been a credential.
const leakedSecret = "AKIAIOSFODNN7EXAMPLE"

// newDLPHandler builds a response-inspecting WAF in front of an origin that
// answers with a leaked credential, compressed however the request asked.
func newDLPHandler(t *testing.T) http.Handler {
	t.Helper()

	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	// The origin compresses when asked to, which is what every real origin does
	// and what the reverse proxy forwards the client's Accept-Encoding for.
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "config dump: aws_access_key_id=" + leakedSecret + "\n"
		accept := r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/plain")

		switch {
		case strings.Contains(accept, "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			var out bytes.Buffer
			zw := gzip.NewWriter(&out)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			_, _ = w.Write(out.Bytes())
		case strings.Contains(accept, "deflate"):
			w.Header().Set("Content-Encoding", "deflate")
			var out bytes.Buffer
			fw, _ := flate.NewWriter(&out, flate.DefaultCompression)
			_, _ = fw.Write([]byte(body))
			_ = fw.Close()
			_, _ = w.Write(out.Bytes())
		default:
			_, _ = w.Write([]byte(body))
		}
	}))
}

// TestWAF_DLPSeesCompressedResponses is the regression for the bypass that made
// every response-phase rule a no-op against real traffic: the origin compressed,
// the engine was handed a DEFLATE stream, no rule matched, and the leak was
// reported clean. Every browser sends Accept-Encoding, so this was the default
// case rather than an edge one.
func TestWAF_DLPSeesCompressedResponses(t *testing.T) {
	handler := newDLPHandler(t)

	for _, tc := range []struct {
		name         string
		acceptEncode string
	}{
		{"browser default", "gzip, deflate, br"},
		{"gzip only", "gzip"},
		{"deflate only", "deflate"},
		{"brotli only", "br"},
		{"wildcard", "*"},
		{"no preference", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/config", nil)
			if tc.acceptEncode != "" {
				req.Header.Set("Accept-Encoding", tc.acceptEncode)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("leaked credential was not blocked: status %d, want %d",
					rec.Code, http.StatusForbidden)
			}
			if body := decodeRecorded(t, rec); strings.Contains(body, leakedSecret) {
				t.Errorf("credential reached the client despite DLP: %q", body)
			}
		})
	}
}

// TestWAF_AcceptEncodingRestoredForClient checks the rewrite does not leak into
// the request the rest of the pipeline sees. Access logs and fingerprinting read
// Accept-Encoding, and a client that sent brotli must not be recorded as having
// asked for gzip.
func TestWAF_AcceptEncodingRestoredForClient(t *testing.T) {
	handler := newDLPHandler(t)

	const sent = "br, gzip;q=0.5"
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set("Accept-Encoding", sent)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := req.Header.Get("Accept-Encoding"); got != sent {
		t.Errorf("Accept-Encoding left rewritten: got %q, want %q", got, sent)
	}
}

// TestWAF_CompressedCleanResponsePassesThrough guards the other direction: the
// fix must not break the ordinary case. A compressed response with nothing to
// hide reaches the client still compressed, byte for byte, so the client keeps
// its bandwidth saving and Content-Length stays true.
func TestWAF_CompressedCleanResponsePassesThrough(t *testing.T) {
	d, dialect, _ := db.Open("sqlite::memory:")
	_ = db.Migrate(d, dialect)
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	const clean = "nothing to see here, just prose and a number 12345"
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte(clean))
	_ = zw.Close()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("clean response was blocked: status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding changed: got %q, want gzip", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), compressed.Bytes()) {
		t.Error("compressed body was not forwarded byte for byte")
	}
	if got := decodeRecorded(t, rec); got != clean {
		t.Errorf("body did not survive inspection: got %q, want %q", got, clean)
	}
}

// decodeRecorded returns the recorded body as the client would read it.
func decodeRecorded(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	switch rec.Header().Get("Content-Encoding") {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			// A blocked response replaces the body with plaintext while the
			// origin's header may still be set, which is not a decode failure.
			return rec.Body.String()
		}
		defer func() { _ = zr.Close() }()
		out, _ := io.ReadAll(zr)
		return string(out)
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(rec.Body.Bytes()))
		defer func() { _ = fr.Close() }()
		out, err := io.ReadAll(fr)
		if err != nil && len(out) == 0 {
			return rec.Body.String()
		}
		return string(out)
	default:
		return rec.Body.String()
	}
}
