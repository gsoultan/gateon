// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// BenchmarkReputationBlocker measures the middleware that runs on every route.
//
// router.go appends ReputationBlocker to every chain unconditionally, so
// whatever this costs is paid by every proxied request whether or not the
// deployment has ever seen an attack. Scoping the identity to the client's
// network added work here — an address parse and a string build where there used
// to be a field read — and a change to the always-on path is exactly what
// AGENTS.md wants a number for rather than a claim.
//
// The request is built once outside the timed loop. Building it inside would
// measure httptest.NewRequest parsing a raw HTTP/1.1 message and allocating a
// 4KB bufio.Reader per iteration, which is how the infrastructure-chain
// benchmark in this package came to be 94% harness (see bench_test.go).
func BenchmarkReputationBlocker(b *testing.B) {
	h := ReputationBlocker("bench-route")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
	req.RemoteAddr = "203.0.113.42:51234"
	rs := &request.RequestState{
		JA4Plus: "t13d1516h2_8daaf6152771_b0da82dd1658",
	}
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, rs))

	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		// The cache on RequestState is what keeps several middlewares on one
		// request from each rebuilding the identity. Clearing it per iteration
		// measures the cold path — one request's first consumer — which is the
		// cost this change actually introduced.
		rs.ReputationID = ""
		h.ServeHTTP(w, req)
	}
}

// BenchmarkReputationBlocker_Cached measures the warm path.
//
// Once any middleware on the request has resolved the identity, the rest read it
// from the request state. Most routes have several reputation consumers — the
// blocker, proof-of-work, the tarpit, deception — so this is what all but the
// first of them pay.
func BenchmarkReputationBlocker_Cached(b *testing.B) {
	h := ReputationBlocker("bench-route-cached")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
	req.RemoteAddr = "203.0.113.42:51234"
	rs := &request.RequestState{
		JA4Plus: "t13d1516h2_8daaf6152771_b0da82dd1658",
	}
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, rs))

	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		h.ServeHTTP(w, req)
	}
}
