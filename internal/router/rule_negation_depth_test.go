// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A route rule is operator input bounded only by the management API's 1 MiB
// body cap, and parseRule used to recurse once per leading '!'. At roughly
// 2.4 KB of stack per frame, somewhere between 350,000 and 450,000 of them
// exhaust the 1 GB goroutine stack. That is a fatal error rather than a panic:
// neither net/http's per-request recover nor the route chain's Recovery
// middleware can catch it, so the process exits.
//
// The rule is parsed lazily -- by SelectRouteFromSlice on the first request
// that reaches the route, and by HostFromRule inside the TLS handshake -- so
// saving such a route did not fail. The next matching request took the gateway
// down, and so did the first one after every restart, because the route was
// persisted. Both entry points are driven here, with a chain just under the
// body cap and with both parities, so the negation still has to mean something
// once it no longer recurses.
func TestLongNegationChainDoesNotExhaustTheStack(t *testing.T) {
	const bangs = 1<<20 - 64 // even, and within the 1 MiB body cap with the Host() suffix
	for _, tc := range []struct {
		name      string
		bangs     int
		wantMatch bool
	}{
		{name: "even chain cancels out", bangs: bangs, wantMatch: true},
		{name: "odd chain negates", bangs: bangs + 1, wantMatch: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := strings.Repeat("!", tc.bangs) + "Host(`a.example.com`)"

			if got := HostFromRule(rule); got != "a.example.com" {
				t.Fatalf("HostFromRule = %q, want %q", got, "a.example.com")
			}

			routes := []*gateonv1.Route{{Id: "negated", Rule: rule}}
			req, err := http.NewRequest(http.MethodGet, "http://a.example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			got := SelectRouteFromSlice(req, routes)
			if matched := got != nil; matched != tc.wantMatch {
				t.Fatalf("route matched = %v, want %v (%d leading '!')", matched, tc.wantMatch, tc.bangs)
			}
		})
	}
}
