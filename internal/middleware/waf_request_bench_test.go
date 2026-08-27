// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// benchRequestHandler builds a WAF over a no-op origin.
//
// withInbound toggles EnableDLP, which at this configuration selects exactly
// the request-phase data-leak rules and nothing else: response inspection is
// off, so the response-phase half of the corpus is not loaded either way. The
// delta between the two benchmarks is therefore those 19 rules alone.
func benchRequestHandler(b *testing.B, withInbound bool) http.Handler {
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
		EnableDLP:        withInbound,
		ParanoiaLevel:    2,
		WafRules:         store,
		RequestBodyLimit: 1024 * 1024,
		Origins:          []string{"bench.local"},
	})
	if err != nil {
		b.Fatalf("create WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// benchRequest drives a JSON POST of the given size through the handler. The
// body is ordinary application traffic: no secret, no attack, which is the
// shape ~all real requests have and therefore the one whose cost matters.
func benchRequest(b *testing.B, handler http.Handler, size int) {
	var body bytes.Buffer
	body.WriteString(`{"items":[`)
	for body.Len() < size {
		body.WriteString(`{"sku":"AB-1234","qty":2,"note":"ship to the usual address"},`)
	}
	body.WriteString(`{"sku":"ZZ-0000","qty":1}]}`)
	payload := body.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		req := httptest.NewRequest(http.MethodPost, "/orders", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// BenchmarkWAFRequestWithInboundDLP measures the request path with the
// request-phase data-leak rules loaded.
func BenchmarkWAFRequestWithInboundDLP(b *testing.B) {
	benchRequest(b, benchRequestHandler(b, true), 16<<10)
}

// BenchmarkWAFRequestWithoutInboundDLP is the same path with those 19 rules
// removed, so the delta between the two is their whole cost.
func BenchmarkWAFRequestWithoutInboundDLP(b *testing.B) {
	benchRequest(b, benchRequestHandler(b, false), 16<<10)
}
