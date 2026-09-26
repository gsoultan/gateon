// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// doublingFragments returns a query whose fragments each spread the next one
// twice, n deep: under 2 KB of text whose full expansion has 2^n leaves.
func doublingFragments(n int, leaf string) string {
	var b strings.Builder
	b.WriteString("query Q { ...F0 }")
	for i := range n {
		fmt.Fprintf(&b, " fragment F%d on Query { ...F%d ...F%d }", i, i+1, i+1)
	}
	fmt.Fprintf(&b, " fragment F%d on Query { %s }", n, leaf)
	return b.String()
}

// The firewall's walkers -- introspection, depth, complexity and field auth --
// followed every fragment spread afresh, guarding only against cycles. A
// fragment spread twice is walked twice, so fragments that each spread the next
// one twice made every walk exponential in their number: a query of about a
// kilobyte held a request goroutine on the CPU for hours, and a handful of them
// starved the gateway -- in the middleware whose job is to refuse expensive
// queries. Each fragment is now walked once per document.
//
// The analysis case also pins the arithmetic that walking once makes
// reachable: 64 doublings is a complexity of 2^64, which wraps an int to zero
// and would sail under MaxComplexity if it were not saturated. The field-auth
// case uses a permitted leaf, because a denied one ends the walk at the first
// leaf and never reaches the blow-up.
func TestGraphQLFirewallWalksEachFragmentOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  GraphQLFirewallConfig
		leaf string
		want int
	}{
		{"analysis", GraphQLFirewallConfig{MaxComplexity: 1000}, "a", http.StatusForbidden},
		{"field auth", GraphQLFirewallConfig{Introspection: true, FieldClaims: map[string]string{"secret": "admin"}}, "a", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mw := GraphQLFirewall(tc.cfg)
			query := doublingFragments(64, tc.leaf)

			// The request runs on its own goroutine so a regression fails this
			// test instead of hanging the package until the global timeout.
			got := make(chan int, 1)
			go func() { got <- graphqlPost(t, mw, query, nil) }()
			select {
			case status := <-got:
				if status != tc.want {
					t.Fatalf("status = %d, want %d", status, tc.want)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the firewall did not answer a 2 KB query in 30s: fragment spreads are being expanded, not walked once")
			}
		})
	}
}
