// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"strings"
	"testing"
)

// gqlparser is a recursive-descent parser with no depth limit of its own, and
// the firewall handed it whatever the client sent, up to the 10 MiB body cap.
// A query nested a million levels deep -- two or three megabytes of brackets --
// exhausts the 1 GB goroutine stack inside the parser. That is a fatal error,
// not a panic: net/http's recover cannot catch it, so one unauthenticated POST
// to any route carrying this middleware took the whole gateway down. Selection
// sets and list values recurse through different parser paths, so both are
// driven here.
func TestGraphQLFirewallRefusesNestingPastTheParserStack(t *testing.T) {
	const levels = 1_000_000
	mw := GraphQLFirewall(GraphQLFirewallConfig{Introspection: true})
	for _, tc := range []struct {
		name  string
		query string
		want  int
	}{
		{"selection sets", strings.Repeat("{a", levels) + strings.Repeat("}", levels), http.StatusBadRequest},
		{"list values", "{a(x:" + strings.Repeat("[", levels) + strings.Repeat("]", levels) + ")}", http.StatusBadRequest},
		{"ordinary depth", strings.Repeat("{a", 64) + strings.Repeat("}", 64), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := graphqlPost(t, mw, tc.query, nil); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

// The nesting limit reads brackets the way the parser's lexer does. Brackets
// inside strings, block strings and comments are content, so they neither
// count toward the limit nor cancel it: counting them naively would let
// closing brackets in a string argument cancel out the real nesting around it,
// and would refuse a query whose only deep brackets are inside a string.
func TestGraphQLNestingLimitReadsBracketsLikeTheLexer(t *testing.T) {
	mw := GraphQLFirewall(GraphQLFirewallConfig{Introspection: true})

	var hidden strings.Builder
	for range maxGraphQLNesting + 1 {
		hidden.WriteString(`{a(s:"}}}}]]]]))))")`)
	}
	hidden.WriteString("{b" + strings.Repeat("}", maxGraphQLNesting+2))

	deepContent := `{a(s:"` + strings.Repeat("{[(", 2*maxGraphQLNesting) + `", ` +
		`t:"""` + strings.Repeat("{", 2*maxGraphQLNesting) + `\"""` + strings.Repeat("[", 2*maxGraphQLNesting) + `""")` +
		" # " + strings.Repeat("(", 2*maxGraphQLNesting) + "\n{b}}"

	for _, tc := range []struct {
		name  string
		query string
		want  int
	}{
		{"closing brackets in strings cannot hide nesting", hidden.String(), http.StatusBadRequest},
		{"brackets in strings and comments are content", deepContent, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := graphqlPost(t, mw, tc.query, nil); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}
