// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

func TestResponseBodyInspectable(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bool
	}{
		// Read: anything a rule could match across.
		{"text/html; charset=utf-8", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/vnd.api+json", true},
		{"application/problem+json", true},
		{"application/xml", true},
		{"application/atom+xml", true},
		{"application/javascript", true},
		{"application/x-www-form-urlencoded", true},
		{"multipart/mixed; boundary=x", true},
		{"text/csv", true},

		// Read: an unlabelled or unfamiliar body is where a leak hides best.
		{"", true},
		{"   ", true},
		{"model/gltf+json", true},
		{"application/vnd.acme.thing", true},

		// Skip: opaque to a byte-level rule, and the expensive half of DLP.
		{"image/png", false},
		{"image/jpeg", false},
		{"video/mp4", false},
		{"audio/mpeg", false},
		{"font/woff2", false},
		{"application/pdf", false},
		{"application/zip", false},
		{"application/octet-stream", false},
		{"application/wasm", false},
		{"application/grpc+proto", false},
		{"application/vnd.ms-fontobject", false},
		{"application/epub+zip", false},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			if got := responseBodyInspectable(tc.contentType); got != tc.want {
				t.Errorf("responseBodyInspectable(%q) = %v, want %v",
					tc.contentType, got, tc.want)
			}
		})
	}
}

// TestWAF_BinaryResponseIsNotBuffered proves the gate does what it is for: a
// binary body reaches the client byte for byte and never enters the buffer. The
// payload deliberately contains a string a DLP rule matches, because the point
// is that the type — not the content — is what takes it off the inspection path.
func TestWAF_BinaryResponseIsNotBuffered(t *testing.T) {
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

	// A PNG header followed by bytes that happen to spell a credential.
	payload := append([]byte("\x89PNG\r\n\x1a\n"), []byte(leakedSecret)...)

	var captured *wafResponseWriter
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		if ww, ok := w.(*wafResponseWriter); ok {
			captured = ww
		}
		_, _ = w.Write(payload)
	}))

	req := httptest.NewRequest(http.MethodGet, "/logo.png", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("binary response was blocked: status %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Error("binary body was not forwarded byte for byte")
	}
	if captured == nil {
		t.Fatal("response writer was not the WAF writer")
	}
	if !captured.skipBody {
		t.Error("image/png response was put on the inspection path")
	}
	if captured.buf != nil {
		t.Error("image/png response took a buffer from the pool")
	}
}

// TestWAF_HoldBackBufferIsReturned checks the pooled buffer is released rather
// than leaked. A buffer still owned by a finished response is one that the next
// response cannot reuse, which is the allocation the pool exists to avoid.
func TestWAF_HoldBackBufferIsReturned(t *testing.T) {
	handler := newDLPHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The DLP handler blocks, which is the path where a buffer is easiest to
	// strand: block() resets it and returns early.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected the leak to be blocked, got %d", rec.Code)
	}
	// Two more responses through the same handler must not panic on a buffer
	// that was returned to the pool while still referenced.
	for range 2 {
		r2 := httptest.NewRequest(http.MethodGet, "/config", nil)
		r2.Header.Set("Accept-Encoding", "gzip")
		handler.ServeHTTP(httptest.NewRecorder(), r2)
	}
}

// countingFlushWriter records whether the WAF writer let a Flush reach the
// client, and how many times the status line was written.
type countingFlushWriter struct {
	http.ResponseWriter
	flushes      int
	headerWrites int
}

func (c *countingFlushWriter) WriteHeader(status int) {
	c.headerWrites++
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingFlushWriter) Flush() {
	c.flushes++
}

// TestWAF_UninspectedResponseStreams covers the branch the content-type gate
// made reachable. A response that is not being held back is already committed,
// so Flush has to reach the client — a video segment or a large download that
// never flushes is a stalled one — and finish must not write the status line a
// second time, which on a real server is a "superfluous WriteHeader" log line
// per response.
func TestWAF_UninspectedResponseStreams(t *testing.T) {
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

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(http.StatusOK)
		for range 3 {
			_, _ = w.Write([]byte("segment"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))

	counter := &countingFlushWriter{ResponseWriter: httptest.NewRecorder()}
	handler.ServeHTTP(counter, httptest.NewRequest(http.MethodGet, "/clip.mp4", nil))

	if counter.flushes != 3 {
		t.Errorf("streaming response flushed %d times, want 3", counter.flushes)
	}
	if counter.headerWrites != 1 {
		t.Errorf("status line written %d times, want 1", counter.headerWrites)
	}
}

// TestWAF_MastercardInGzippedResponseIsBlocked is the end-to-end case both DLP
// fixes had to land for: a brand the old Visa-only regex never matched, inside a
// gzipped body the old response path could not read. Either defect alone was
// enough to let it through.
func TestWAF_MastercardInGzippedResponseIsBlocked(t *testing.T) {
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

	const pan = "5555555555554444" // Mastercard test number, never issued.
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"customer":"ada","card":"` + pan + `"}`
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			var out bytes.Buffer
			zw := gzip.NewWriter(&out)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			_, _ = w.Write(out.Bytes())
			return
		}
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/customer", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("card leak not blocked: status %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), pan) {
		t.Error("card number reached the client")
	}
}
