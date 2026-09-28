// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
)

// BenchmarkRecordPerRequest measures what the Metrics middleware records once
// per finished request -- the per-IP counters the anomaly detector reads among
// them -- for the answers brute-force counting tells apart: a success, a GET
// refused 401 (a tab polling with an expired session), a POST refused 401 (a
// login attempt), a GET refused 401 that carried Basic credentials, and a POST
// refused 401 carrying the request state every entrypoint request has, which
// is where a refusal the gateway made itself is marked (ADR 0031).
func BenchmarkRecordPerRequest(b *testing.B) {
	for _, tc := range []struct {
		name, method, authorization string
		status                      int
		state                       bool
	}{
		{"ok-get", http.MethodGet, "", http.StatusOK, false},
		{"401-get-session", http.MethodGet, "", http.StatusUnauthorized, false},
		{"401-post", http.MethodPost, "", http.StatusUnauthorized, false},
		{"401-get-basic", http.MethodGet, "Basic dXNlcjpndWVzcw==", http.StatusUnauthorized, false},
		{"401-post-state", http.MethodPost, "", http.StatusUnauthorized, true},
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
			if tc.state {
				req = req.WithContext(request.WithState(context.Background(), &request.RequestState{}))
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
