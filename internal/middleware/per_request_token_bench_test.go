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

// BenchmarkRecordPerRequestTokenRefusal is BenchmarkRecordPerRequest's
// "401-post-state" case with the request marked as the gateway's own token
// refusal (ADR 0031): the path an expired-session Connect poll takes, on which
// the brute-force count reads the mark and skips the request.
func BenchmarkRecordPerRequestTokenRefusal(b *testing.B) {
	reqURL := *benchURL
	req := &http.Request{
		Method: http.MethodPost, URL: &reqURL, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header, 2), Host: benchURL.Host, RemoteAddr: "203.0.113.7:54321",
		RequestURI: benchRequestURI, Body: http.NoBody,
	}
	req = req.WithContext(request.WithState(context.Background(), &request.RequestState{Refused: request.RefusalToken}))
	s := perRequestSample{
		clientIP: "203.0.113.7", status: http.StatusUnauthorized, country: "US", host: benchURL.Host,
		bytesIn: 512, bytesOut: 1024, duration: time.Millisecond, bandwidth: 1536,
	}
	recordPerRequest(req, s) // the address's entry exists, as it does for a returning client

	b.ReportAllocs()
	for b.Loop() {
		recordPerRequest(req, s)
	}
}
