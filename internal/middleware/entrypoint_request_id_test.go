// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// The entrypoint answers every request with its ID, the one downstream
// middleware and the trace see: the one the client sent, or a fresh one. It
// assigns the header value rather than calling Set, so this pins that the
// assignment is still the single, canonical header Set produced.
func TestEntryPointAnswersWithTheRequestID(t *testing.T) {
	var seen string
	h := EntryPoint("web", "web", false)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = GetRequestState(r).RequestID
	}))

	for _, tc := range []struct{ name, sent string }{{"generated", ""}, {"supplied", "client-abc"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.sent != "" {
				r.Header.Set("x-request-id", tc.sent)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)

			got := rr.Header().Values(request.HeaderRequestID)
			if len(got) != 1 || got[0] != seen {
				t.Fatalf("response carries %q, the request state %q", got, seen)
			}
			if tc.sent != "" && seen != tc.sent {
				t.Fatalf("supplied id %q replaced by %q", tc.sent, seen)
			}
			if tc.sent == "" && !strings.HasPrefix(seen, "req-") {
				t.Fatalf("generated id %q", seen)
			}
			if len(rr.Header()) != 1 {
				t.Fatalf("headers %v, want only the request id", rr.Header())
			}
		})
	}
}
