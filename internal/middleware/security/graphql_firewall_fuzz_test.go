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

// graphQLStructuredSeeds are well-formed documents that use the parts of the
// grammar the first seed set never reached. The fuzzer mutates bytes, so from
// `{ user { name } }` it almost never assembles a variable definition, a
// directive or an inline fragment by chance, and the weekly runs had stopped
// finding new coverage on the seeds above. Each line here is a valid document
// whose mutations stay close to valid, which is where a parser and the four
// walks over its tree disagree with each other. The ones that name `secret`,
// `expensive` or `__schema` put a forbidden thing somewhere a check has to
// look for it: behind an alias, a fragment, an inline fragment, a directive,
// or a second operation.
var graphQLStructuredSeeds = []string{
	// Variables: definitions, defaults, list and non-null types, use in args.
	`query Q($id: ID!, $n: Int = 10) { user(id: $id) { posts(first: $n) { title } } }`,
	`query ($ids: [ID!]! = ["1", "2"], $f: Filter = {and: [{name: "x"}]}) { users(ids: $ids, filter: $f) { id } }`,
	// Directives on fields, fragments, inline fragments and definitions.
	`query ($s: Boolean!) { user { name @include(if: $s) secret @skip(if: true) } }`,
	`query ($a: Int @deprecated(reason: "x")) @live { x @a @b(c: 1) @d(e: {f: [1, 2]}) }`,
	`{ ...F @include(if: false) } fragment F on Query @x { secret }`,
	// Inline fragments, with and without a type condition.
	`{ node(id: 1) { ... on User { name } ... @include(if: true) { id } ... { __typename } } }`,
	`{ ... on Query { __schema { types { name } } } }`,
	// Aliases: the same costly or claimed field under other names.
	`{ s: secret }`,
	`{ a: expensive b: expensive c: expensive d: expensive e: expensive f: expensive }`,
	`{ s: __schema { queryType { name } } t: __type(name: "User") { fields { name } } }`,
	// More than one operation, and every operation type.
	`query A { user { name } } query B { secret }`,
	`query A { user { name } } mutation M($in: UserInput!) { createUser(input: $in) { id } }`,
	`subscription S { events(filter: {kind: [A, B]}) { id payload } }`,
	// Depth and introspection reached only through fragments.
	`{ a { ...F } } fragment F on A { b { c { d { e { f { g } } } } } }`,
	`{ ...I } fragment I on Query { ...J } fragment J on Query { __schema { types { name } } }`,
	// Lexical corners: comments, commas, escapes, block strings, a BOM.
	"# leading comment }\n{ user # trailing }\n { name } }",
	`{ user,,, { name, id, }, }`,
	`{ a(s: "\u007d\u007b\"\\", t: """x \""" } {""", u: 1.5e-3, v: -0, w: null, x: ENUM) }`,
	"\ufeff{ user { name } }",
	"{\r\n\tuser\r\n\t{\r\n\t\tname\r\n\t}\r\n}",
}

// graphQLEnvelopeSeeds are whole POST bodies, for the mode that sends its
// input as the raw body: they reach the JSON decode in readGraphQLQuery with
// shapes a real client sends (variables, operationName, extensions) and the
// ones a parser differential lives in (a repeated key, a key differing only in
// case, a batch, a query that is not a string, escapes inside the query).
var graphQLEnvelopeSeeds = []string{
	`{"query":"query($id:ID!){user(id:$id){name}}","variables":{"id":"1"},"operationName":null}`,
	`{"query":"query A{a} query B{secret}","operationName":"B","variables":{}}`,
	`{"query":"{ user { name } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`,
	`{"query":"{ secret }","query":"{ user }"}`,
	`{"query":"{ secret }","QUERY":"{ user }"}`,
	`[{"query":"{ secret }"},{"query":"{ user }"}]`,
	`{"query":{"query":"{ secret }"}}`,
	`{"query":"{ \u0073ecret }"}`,
	`{"query":"{ user }"} {"query":"{ secret }"}`,
	`{"variables":{"q":"{ secret }"}}`,
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
	for _, seeds := range [][]string{graphQLFuzzSeeds, graphQLStructuredSeeds} {
		for _, s := range seeds {
			for mode := uint8(0); mode < 3; mode++ {
				f.Add(s, mode)
			}
		}
	}
	for _, s := range graphQLEnvelopeSeeds {
		f.Add(s, uint8(2))
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
	for _, seeds := range [][]string{graphQLFuzzSeeds, graphQLStructuredSeeds} {
		for _, s := range seeds {
			f.Add(s)
		}
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

// TestGraphQLStructuredSeedsParse keeps the structured seeds honest: each is a
// document the firewall's own parser accepts. A seed it rejects only reaches
// the parse-error refusal, so the walks over the tree -- depth, cost, claims,
// introspection -- would never see the grammar the seed was added to cover.
func TestGraphQLStructuredSeedsParse(t *testing.T) {
	for _, s := range graphQLStructuredSeeds {
		if graphQLNestingExceeds(s, maxGraphQLNesting) {
			t.Fatalf("seed exceeds the nesting guard: %q", s)
		}
		if _, err := parseGraphQLQuery(s); err != nil {
			t.Fatalf("seed does not parse: %v\n%q", err, s)
		}
	}
}
