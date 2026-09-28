// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"testing"
	"time"
)

// BenchmarkRecordPerRequest measures what the Metrics middleware records once
// per finished request -- the per-IP counters the anomaly detector reads among
// them -- for the answers brute-force counting tells apart: a success, a GET
// refused 401 (a tab polling with an expired session), a POST refused 401 (a
// login attempt), and a GET refused 401 that carried Basic credentials.
func BenchmarkRecordPerRequest(b *testing.B) {
	for _, tc := range []struct {
		name, method, authorization string
		status                      int
	}{
		{"ok-get", http.MethodGet, "", http.StatusOK},
		{"401-get-session", http.MethodGet, "", http.StatusUnauthorized},
		{"401-post", http.MethodPost, "", http.StatusUnauthorized},
		{"401-get-basic", http.MethodGet, "Basic dXNlcjpndWVzcw==", http.StatusUnauthorized},
	} {
		b.Run(tc.name, func(b *testing.B) {
			reqURL := *benchURL
			req := &http.Request{
				Method: tc.method, URL: &reqURL, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header, 2), Host: benchURL.Host, RemoteAddr: "203.0.113.7:54321",
				RequestURI: benchRequestURI, Body: http.NoBody,
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			s := perRequestSample{
				clientIP: "203.0.113.7", status: tc.status, country: "US", host: benchURL.Host,
				bytesIn: 512, bytesOut: 1024, duration: time.Millisecond, bandwidth: 1536,
			}
			recordPerRequest(req, s) // the address's entry exists, as it does for a returning client

			b.ReportAllocs()
			for b.Loop() {
				recordPerRequest(req, s)
			}
		})
	}
}
