// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// Every walker in the firewall -- introspection, depth, complexity and
// field-level auth -- descended into fields and inline fragments and skipped
// FragmentSpread, so `query { ...F } fragment F on Query { ... }` hid whatever
// F contained from all four checks. Field-level auth additionally read the
// caller's claims from a request header nothing in the gateway sets, so the
// client could supply them.

// graphqlPost sends one GraphQL request through mw and returns the status.
func graphqlPost(t *testing.T, mw kind.Middleware, query string, ctxClaims jwt.MapClaims) int {
	t.Helper()
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	if ctxClaims != nil {
		req = req.WithContext(auth.InjectContext(req.Context(), ctxClaims))
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	return rec.Code
}

func TestGraphQLFirewallSeesThroughFragmentSpreads(t *testing.T) {
	cases := []struct {
		name  string
		cfg   GraphQLFirewallConfig
		query string
	}{
		{"introspection", GraphQLFirewallConfig{Introspection: false},
			`query Q { ...F } fragment F on Query { __schema { types { name } } }`},
		{"depth", GraphQLFirewallConfig{MaxDepth: 2},
			`query Q { ...A } fragment A on Query { user { ...B } } fragment B on User { profile { bio } }`},
		{"complexity", GraphQLFirewallConfig{MaxComplexity: 3},
			`query Q { ...A } fragment A on Query { a b c d }`},
		{"field auth", GraphQLFirewallConfig{FieldClaims: map[string]string{"secret": "admin"}},
			`query Q { ...A } fragment A on Query { secret }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := graphqlPost(t, GraphQLFirewall(tc.cfg), tc.query, nil); code != http.StatusForbidden {
				t.Errorf("hidden behind a fragment spread: got %d, want 403", code)
			}
		})
	}
}

func TestGraphQLFirewallSurvivesAFragmentCycle(t *testing.T) {
	mw := GraphQLFirewall(GraphQLFirewallConfig{MaxDepth: 2, MaxComplexity: 10, FieldClaims: map[string]string{"x": "y"}})
	// A cyclic fragment is invalid GraphQL, but the parser accepts it; the
	// walkers must terminate rather than recurse until the stack is gone.
	code := graphqlPost(t, mw, `query Q { ...A } fragment A on Query { a { ...A } }`, nil)
	if code != http.StatusForbidden && code != http.StatusOK && code != http.StatusBadRequest {
		t.Errorf("unexpected status %d", code)
	}
}

func TestGraphQLFieldAuthIgnoresClientSuppliedClaims(t *testing.T) {
	mw := GraphQLFirewall(GraphQLFirewallConfig{FieldClaims: map[string]string{"secret": "admin"}})
	body, _ := json.Marshal(map[string]string{"query": "{ secret }"})
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	req.Header.Set("X-Gateon-Claims", "admin")
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a client-supplied X-Gateon-Claims header unlocked a claim-gated field: got %d, want 403", rec.Code)
	}
}

func TestGraphQLFieldAuthReadsTheVerifiedClaims(t *testing.T) {
	mw := GraphQLFirewall(GraphQLFirewallConfig{FieldClaims: map[string]string{"secret": "admin", "me": "sub"}})
	claims := jwt.MapClaims{"sub": "u1", "roles": []any{"admin"}}
	if code := graphqlPost(t, mw, `{ secret me }`, claims); code != http.StatusOK {
		t.Errorf("verified claims did not unlock the gated fields: got %d, want 200", code)
	}
	if code := graphqlPost(t, mw, `{ secret }`, jwt.MapClaims{"sub": "u2"}); code != http.StatusForbidden {
		t.Errorf("a token without the role reached the gated field: got %d, want 403", code)
	}
}

func TestGraphQLFirewallDoesNotCacheOversizedQueries(t *testing.T) {
	mw := GraphQLFirewall(GraphQLFirewallConfig{MaxDepth: 10})
	query := "{ a " + strings.Repeat(" ", 1<<20) + "}"
	if code := graphqlPost(t, mw, query, nil); code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
	if graphqlQueryCache.Contains(query) {
		t.Errorf("a %d-byte attacker-chosen query was retained in the analysis cache; 2048 such entries would hold %d MiB",
			len(query), 2048*len(query)>>20)
	}
}
