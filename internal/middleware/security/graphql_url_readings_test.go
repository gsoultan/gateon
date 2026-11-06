// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGraphQLFirewallChecksEveryURLReading closes three ways a query in the
// URL reached the origin unanalysed.
//
// The URL was checked on GET only, and read as values["query"] exactly. So
// `?QUERY=` came back empty and was forwarded, while ASP.NET Core (Hot
// Chocolate) matches parameter names case-insensitively and ran it; a POST
// was judged by its body alone, while express-graphql prefers the URL's query
// to the body's; and any other method passed the URL through untouched.
func TestGraphQLFirewallChecksEveryURLReading(t *testing.T) {
	const intro = "%7B__schema%7Btypes%7Bname%7D%7D%7D"
	cases := []struct {
		name, method, url, body string
		wantReached             bool
	}{
		{"GET case-variant name", http.MethodGet, "/graphql?QUERY=" + intro, "", false},
		{"POST URL query, empty body", http.MethodPost, "/graphql?query=" + intro, `{}`, false},
		{"POST URL query, benign body", http.MethodPost, "/graphql?query=" + intro, `{"query":"{a}"}`, false},
		{"PUT URL query", http.MethodPut, "/graphql?query=" + intro, "", false},
		// Controls: the bound is on introspection, not on URLs.
		{"POST benign body, unrelated URL params", http.MethodPost, "/graphql?trace=1", `{"query":"{a}"}`, true},
		{"GET benign query", http.MethodGet, "/graphql?query=%7Ba%7D", "", true},
		{"GET no GraphQL params", http.MethodGet, "/graphql?page=2", "", true},
	}
	mw, err := NewGraphQLFirewall(map[string]string{"introspection": "false"})
	if err != nil {
		t.Fatalf("NewGraphQLFirewall: %v", err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reached := false
			h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
			var r *http.Request
			if c.body != "" {
				r = httptest.NewRequest(c.method, "http://x"+c.url, strings.NewReader(c.body))
				r.Header.Set("Content-Type", "application/json")
			} else {
				r = httptest.NewRequest(c.method, "http://x"+c.url, nil)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if reached != c.wantReached {
				t.Errorf("reached origin = %v, want %v (status %d)", reached, c.wantReached, rec.Code)
			}
		})
	}
}
