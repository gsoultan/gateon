// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestEntrypointStripsFrameworkInternalHeaders sends, through the entrypoint
// middleware every listener starts with, the headers a framework believes only
// from infrastructure. What the next handler sees is what every route, policy,
// auth service and backend sees.
//
// Root cause of what this guards: the gateway forwarded a client's
// X-Middleware-Subrequest, X-Original-URL and method-override headers
// untouched, so a backend that honours them served a path or ran a method the
// gateway never matched, filtered or authorised (CVE-2025-29927 class).
func TestEntrypointStripsFrameworkInternalHeaders(t *testing.T) {
	var seen http.Header
	h := EntryPoint("ep", "ep", false)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))

	counter := telemetry.ClientInternalHeadersStrippedTotal.WithLabelValues("X-Middleware-Subrequest")
	before := counterValue(t, counter)

	r := httptest.NewRequest(http.MethodPost, "/public", nil)
	r.Header.Set("x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware")
	r.Header.Set("X-Original-URL", "/admin")
	r.Header.Set("X-Rewrite-URL", "/admin")
	r.Header.Set("X-HTTP-Method-Override", "DELETE")
	// The alias spellings a header-folding backend reads as the same names.
	r.Header["X_original_url"] = []string{"/admin"}
	r.Header["X.http.method.override"] = []string{"DELETE"}
	// Controls: ordinary headers must arrive.
	r.Header.Set("Authorization", "Bearer t")
	r.Header.Set("X-Request-Source", "mobile")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil {
		t.Fatal("the next handler was not reached")
	}
	for key := range seen {
		for _, name := range request.InternalHeaders {
			if request.FoldHeaderName(key) == request.FoldHeaderName(name) {
				t.Errorf("%q reached the handler", key)
			}
		}
	}
	if seen.Get("Authorization") == "" || seen.Get("X-Request-Source") == "" {
		t.Errorf("an ordinary header was removed: %v", seen)
	}
	if got := counterValue(t, counter) - before; got != 1 {
		t.Errorf("the stripped header was counted %v times, want 1", got)
	}
}
