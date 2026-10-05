// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

func TestWAFEntropyFalsePositive(t *testing.T) {
	// A typical high-entropy token (e.g., a JWT-like string)
	highEntropyToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoyNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	cfg := WAFConfig{
		RouteID: "test-route",
	}

	mw, err := WAF(cfg)
	if err != nil {
		t.Fatalf("Failed to create WAF middleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: High entropy Authorization header (should NOT be blocked if we are smart)
	req1 := httptest.NewRequest("GET", "/api/data", nil)
	req1.Header.Set("Authorization", "Bearer "+highEntropyToken)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code == http.StatusForbidden {
		t.Errorf("Legitimate high-entropy Authorization header was blocked with 403")
	}

	// Case 2: High entropy unknown header (currently blocked if > 64 chars and > 5.8 entropy)
	// We use a string with very high entropy (simulating shellcode/random data)
	highEntropyString := "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
	req2 := httptest.NewRequest("GET", "/api/data", nil)
	req2.Header.Set("X-Custom-Data", highEntropyString)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	// We expect this to be blocked because it's an unknown header and very high entropy.
	// This is the intended behavior for "security fast-path".
	if rec2.Code != http.StatusForbidden {
		t.Errorf("Unknown high-entropy header was NOT blocked, but should be")
	}
}

// TestBodyEntropyForwardsTheBodyOnce is DP-F4. peekBody put the peeked bytes
// back twice -- once before its error check and again after -- so the request
// that left the WAF carried the head of its body twice under the original
// Content-Length. Every POST to a route with enable_body_entropy reached the
// proxy longer than it declared (502), and the engine inspected a body the
// client never sent.
func TestBodyEntropyForwardsTheBodyOnce(t *testing.T) {
	mw, err := WAF(WAFConfig{RouteID: "entropy-body", EnableBodyEntropy: true, RequestBodyLimit: 1 << 20})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	var got []byte
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	sent := strings.Repeat("an ordinary order note, nothing to see here. ", 4)
	req := httptest.NewRequest(http.MethodPost, "/orders", strings.NewReader(sent))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if string(got) != sent {
		t.Fatalf("upstream received %d bytes, the client sent %d (Content-Length %d):\n%q",
			len(got), len(sent), req.ContentLength, got)
	}
}

// TestPeekBodyRestoresTheStreamExactly pins the helper itself, including the
// error path: bytes read before a failure are already off the client's stream
// and have to be put back, once.
func TestPeekBodyRestoresTheStreamExactly(t *testing.T) {
	for _, tc := range []struct {
		name string
		body io.Reader
		want string
	}{
		{"shorter than the peek", strings.NewReader("hello"), "hello"},
		{"longer than the peek", strings.NewReader(strings.Repeat("a", 10) + "tail"), strings.Repeat("a", 10) + "tail"},
		{"read error after some bytes", io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(errPeek)), "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(tc.body))
			_, _ = peekBody(r, 10)
			rest, _ := io.ReadAll(r.Body)
			if string(rest) != tc.want {
				t.Errorf("body after peek = %q, want %q", rest, tc.want)
			}
		})
	}
}

var errPeek = errors.New("connection reset mid-body")
