// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWAF_GRPCCompatibility(t *testing.T) {
	mw, err := WAF(WAFConfig{})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		ctype      string
		expectCode int
	}{
		{
			name:       "Legit gRPC request",
			method:     "POST",
			ctype:      "application/grpc",
			expectCode: http.StatusOK,
		},
		{
			name:       "Legit gRPC-Web request",
			method:     "POST",
			ctype:      "application/grpc-web",
			expectCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/poseidon.activity.ActivityService/ListCategory", nil)
			req.Header.Set("Content-Type", tc.ctype)
			// gRPC doesn't use Content-Length usually in HTTP/2, but httptest might add it if body is nil?
			// Force it to be absent or handled.

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("%s: expected status %d, got %d", tc.name, tc.expectCode, rr.Code)
			}
		})
	}
}
