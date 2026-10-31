// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// graphQLFuzzSeeds are the shapes the firewall's checks were each written
// against: a plain query, introspection, depth past the limit, a cyclic
// fragment, exponential fragment reuse, a field that needs a claim, and the
// malformed documents a parser is most often wrong about -- unbalanced
// brackets, an unterminated string, and brackets inside a string.
var graphQLFuzzSeeds = []string{
	`{ user { name } }`,
	`{ __schema { types { name } } }`,
	`query { a { b { c { d { e { f } } } } } }`,
	`{ ...F } fragment F on Query { ...F }`,
	`{ ...A } fragment A on Q { ...B ...B } fragment B on Q { ...C ...C } fragment C on Q { x }`,
	`{ secret expensive }`,
	``,
	`{`,
	`}`,
	`{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{`,
	`"unterminated`,
	`{ a(arg: "}}}}") }`,
	`{ a(arg: """block } string""") }`,
	"\x00\xff{",
}

// FuzzGraphQLFirewall drives the whole middleware with an arbitrary query by
// every route a client has into it: the GET query parameter, a POST carrying
// the query in its JSON envelope, and a POST whose raw body is the arbitrary
// bytes (which is how the JSON decode itself gets hostile input). The
// firewall runs on the request goroutine, where a panic is recovered, so the
// crash class here is the nesting guard's purpose -- stack exhaustion is a
// fatal error no recover catches -- and the invariants are about what the
// firewall lets through: a request is either refused or forwarded with the
// bytes it arrived with, never both and never neither.
func FuzzGraphQLFirewall(f *testing.F) {
	for _, s := range graphQLFuzzSeeds {
		for mode := uint8(0); mode < 3; mode++ {
			f.Add(s, mode)
		}
	}

	mw := GraphQLFirewall(GraphQLFirewallConfig{
		MaxDepth:      5,
		MaxComplexity: 50,
		FieldCosts:    map[string]int{"expensive": 10},
		FieldClaims:   map[string]string{"secret": "admin"},
		Introspection: false,
	})

	f.Fuzz(func(t *testing.T, query string, mode uint8) {
		var reached bool
		var forwarded []byte
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			forwarded, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
			w.WriteHeader(http.StatusOK)
		}))

		var req *http.Request
		var sent []byte
		switch mode % 3 {
		case 0:
			req = httptest.NewRequest(http.MethodGet, "/graphql?"+url.Values{"query": {query}}.Encode(), nil)
		case 1:
			sent, _ = json.Marshal(map[string]string{"query": query})
			req = httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(sent))
		default:
			sent = []byte(query)
			req = httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(sent))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if reached && req.Method == http.MethodPost && !bytes.Equal(forwarded, sent) {
			t.Fatalf("mode %d: forwarded body differs from what was sent\n sent=%q\n got=%q", mode%3, sent, forwarded)
		}
		if !reached && rr.Code < 400 {
			t.Fatalf("mode %d: request was neither forwarded nor refused (status %d) for %q", mode%3, rr.Code, query)
		}
	})
}

// FuzzGraphQLAnalysis exercises the parse and the four walks directly, past
// the same nesting guard the middleware applies first. Every cost is summed
// with saturating arithmetic, so a document can never produce a negative
// depth or complexity, and the fragment memo must make a second walk of the
// same document agree with the first: a disagreement means a memo entry was
// read before it was complete, which is exactly the cyclic-fragment case.
func FuzzGraphQLAnalysis(f *testing.F) {
	for _, s := range graphQLFuzzSeeds {
		f.Add(s)
	}
	costs := map[string]int{"expensive": 10, "x": 1 << 30}
	f.Fuzz(func(t *testing.T, query string) {
		if graphQLNestingExceeds(query, maxGraphQLNesting) {
			return
		}
		doc, err := parseGraphQLQuery(query)
		if err != nil {
			return
		}
		d1, c1, i1 := calculateDepth(doc), calculateComplexity(doc, costs), isIntrospectionQuery(doc)
		if d1 < 0 || c1 < 0 {
			t.Fatalf("negative result: depth=%d complexity=%d for %q", d1, c1, query)
		}
		d2, c2, i2 := calculateDepth(doc), calculateComplexity(doc, costs), isIntrospectionQuery(doc)
		if d1 != d2 || c1 != c2 || i1 != i2 {
			t.Fatalf("analysis is not deterministic: (%d,%d,%v) then (%d,%d,%v) for %q", d1, c1, i1, d2, c2, i2, query)
		}
	})
}
