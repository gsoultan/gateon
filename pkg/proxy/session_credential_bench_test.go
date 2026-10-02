// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkServeHTTPCookies measures the proxy with and without the management
// session cookie in the request, which is the cost of removing it (ADR 0041).
// The Cookie line is restored before every iteration because the proxy edits
// the request it is given.
func BenchmarkServeHTTPCookies(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	for _, bc := range []struct{ name, cookie string }{
		{"no-session-cookie", "a=1; b=2; theme=dark; _ga=GA1.2.3"},
		{"session-cookie", "a=1; gateon_session=v4.local.ADMIN; b=2; theme=dark"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			h := credentialTestHandler(backend.URL)
			defer h.Close()
			req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
			line := []string{bc.cookie}
			b.ReportAllocs()
			for b.Loop() {
				line[0] = bc.cookie
				req.Header["Cookie"] = line
				h.ServeHTTP(httptest.NewRecorder(), req)
			}
		})
	}
}
