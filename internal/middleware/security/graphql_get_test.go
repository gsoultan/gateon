// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGraphQLFirewallInspectsGETQueries closes a bypass of every check the
// middleware performs.
//
// The firewall only looked at POST. GraphQL over GET -- query in the URL -- is
// a standard transport that Apollo Server, gqlgen, graphql-go and Hasura all
// accept, so `GET /graphql?query={__schema{...}}` walked past the introspection
// block, the depth limit, the complexity limit and field-level claim auth. The
// client chose which checks ran by choosing a method.
func TestGraphQLFirewallInspectsGETQueries(t *testing.T) {
	cfg := map[string]string{"introspection": "false"}

	mw, err := NewGraphQLFirewall(cfg)
	if err != nil {
		t.Fatalf("NewGraphQLFirewall: %v", err)
	}

	var reached bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet,
		"http://x/graphql?query="+"%7B__schema%7Btypes%7Bname%7D%7D%7D", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if reached {
		t.Error("an introspection query over GET reached the origin; every " +
			"limit this middleware enforces was skipped by choosing a method")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestGraphQLFirewallStillPassesOrdinaryGETs keeps the fix from turning every
// non-GraphQL GET on the route into parse work or a refusal.
func TestGraphQLFirewallStillPassesOrdinaryGETs(t *testing.T) {
	mw, err := NewGraphQLFirewall(map[string]string{"introspection": "false"})
	if err != nil {
		t.Fatalf("NewGraphQLFirewall: %v", err)
	}

	var reached bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "http://x/health", nil))

	if !reached {
		t.Error("a GET with no query parameter was refused")
	}
}
