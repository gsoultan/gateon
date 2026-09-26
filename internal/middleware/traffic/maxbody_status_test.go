// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBodyDeclaredOverTheLimitNeverReachesTheBackend: MaxBytesReader fails the
// read and writes nothing, so an upload over the buffering limit went to the
// backend anyway and came back as whatever the reverse proxy made of the
// broken read -- a 502, counted against the backend.
func TestBodyDeclaredOverTheLimitNeverReachesTheBackend(t *testing.T) {
	reached := false
	h := MaxBodySize(10)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 100)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if reached {
		t.Error("a body declared over the limit reached the backend")
	}

	within := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("small"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, within)
	if rec.Code != http.StatusOK {
		t.Errorf("a body within the limit: status %d, want 200", rec.Code)
	}
}
