// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// These two cover work that used to be redone on every request even though
// nothing about it depends on the request. Both are route-derivable, so the
// benchmark is the proof that they are now derived once.

// BenchmarkHeadersMiddleware runs a config of realistic size. NewHeaders used
// to range the whole map twice per request -- once per direction -- testing
// three prefixes against every key, so the per-request cost grew with the
// number of settings on the route rather than with the number of rules that
// actually matched.
func BenchmarkHeadersMiddleware(b *testing.B) {
	cfg := map[string]string{
		"set_request_X-Service":     "gateway",
		"add_request_X-Trace":       "on",
		"del_request_X-Internal":    "",
		"set_response_X-Frame":      "DENY",
		"add_response_X-Cache-Tag":  "v1",
		"del_response_Server":       "",
		"sts_seconds":               "31536000",
		"sts_include_subdomains":    "true",
		"force_sts_header":          "true",
		"unrelated_knob_one":        "a",
		"unrelated_knob_two":        "b",
		"unrelated_knob_three":      "c",
		"unrelated_knob_four":       "d",
		"unrelated_knob_five":       "e",
	}
	mw, err := NewHeaders(cfg)
	if err != nil {
		b.Fatalf("NewHeaders: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// BenchmarkGRPCWebPassthrough measures a plain HTTP request on a gRPC-Web
// route -- the common case, since the route carries both. GRPCWeb used to
// build a cors.Options literal and call cors.New on it per request, and
// cors.New normalises and compiles the entire policy.
func BenchmarkGRPCWebPassthrough(b *testing.B) {
	mw := GRPCWeb(CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com"},
		AllowCredentials: true,
		MaxAge:           600,
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodPost, "https://example.com/pkg.Svc/Method", nil)
	req.Header.Set("Origin", "https://app.example.com")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}
