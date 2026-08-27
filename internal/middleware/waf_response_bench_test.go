// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// benchResponseHandler builds a response-inspecting WAF over an origin that
// answers with body of the given type and size.
func benchResponseHandler(b *testing.B, contentType string, size int) http.Handler {
	b.Helper()

	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		b.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(b.Context()); err != nil {
		b.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
		// Declared so the off-origin rules are active and the benchmark measures
		// a fully-armed engine rather than one with a family switched off.
		Origins: []string{"bench.local"},
	})
	if err != nil {
		b.Fatalf("create WAF: %v", err)
	}

	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func benchResponse(b *testing.B, contentType string, size int) {
	handler := benchResponseHandler(b, contentType, size)
	req := httptest.NewRequest(http.MethodGet, "/asset", nil)
	req.Header.Set("Accept-Encoding", "identity")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// BenchmarkWAFResponseBinary is the case the content-type gate exists for: a
// body no data-leak rule could match, which used to be held to the ceiling and
// scanned anyway.
func BenchmarkWAFResponseBinary(b *testing.B) { benchResponse(b, "image/png", 256<<10) }

// BenchmarkWAFResponseText is the case that must not regress: a body that is
// genuinely inspected, where the pool replaces a per-response allocation.
func BenchmarkWAFResponseText(b *testing.B) { benchResponse(b, "text/html", 256<<10) }
