// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These two moved here from internal/middleware, where they exercised a second
// copy of IPFilter that nothing outside that file called. The live filter --
// the one start_servers.go wires onto the management listener -- had no
// allow/deny or resolver test at all; these looked like coverage of it and
// were not.
//
// The XFF one also asserted only that an allowed address gets through, which a
// middleware that did nothing would also satisfy. It now asserts both
// directions, so deleting the filter fails it.

func TestIPFilterAllowsInRangeAndDeniesListed(t *testing.T) {
	mw := IPFilter([]string{"192.168.1.0/24"}, []string{"192.168.1.100"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		remoteAddr string
		want       int
	}{
		{"inside the allowed range", "192.168.1.50:12345", http.StatusOK},
		{"explicitly denied, inside the allowed range", "192.168.1.100:12345", http.StatusForbidden},
		{"outside the allowed range", "203.0.113.7:12345", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestIPFilterWithClientIPUsesTheSuppliedResolver(t *testing.T) {
	// A resolver that prefers X-Forwarded-For, as a deployment behind a trusted
	// proxy would supply.
	mw := IPFilterWithClientIP([]string{"203.0.113.50"}, nil, func(r *http.Request) string {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		addr := r.RemoteAddr
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[:i]
		}
		return addr
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name string
		xff  string
		want int
	}{
		// The socket peer is outside the allow list in both cases, so a filter
		// that ignored the resolver would deny the first; one that ignored the
		// allow list would admit the second.
		{"resolver returns an allowed address", "203.0.113.50", http.StatusOK},
		{"resolver returns a disallowed address", "198.51.100.9", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:80"
			req.Header.Set("X-Forwarded-For", tc.xff)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}
