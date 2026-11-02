// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGraphQLFirewallRefusesAmbiguousBodyKeys closes a bypass of every check
// the firewall performs.
//
// The body was decoded with encoding/json into struct{Query string}. That
// matches keys case-insensitively and lets the last duplicate win, so for
// {"query":"<blocked>","QUERY":"<benign>"} the firewall analysed the benign
// query while a backend reading body.query exactly -- every JavaScript server
// -- executed the blocked one. A firewall and a backend that read different
// documents from one body is the request-smuggling shape, one layer up.
func TestGraphQLFirewallRefusesAmbiguousBodyKeys(t *testing.T) {
	const blocked = `{ __schema { types { name } } }`
	cases := map[string]string{
		"case variant last":       `{"query":"` + blocked + `","QUERY":"{ user }"}`,
		"case variant first":      `{"Query":"{ user }","query":"` + blocked + `"}`,
		"exact duplicate":         `{"query":"` + blocked + `","query":"{ user }"}`,
		"escaped duplicate":       `{"query":"` + blocked + `","query":"{ user }"}`,
		"duplicate operationName": `{"query":"{ user }","operationName":"A","OperationName":"B"}`,
		"duplicate variables":     `{"query":"{ user }","variables":{},"VARIABLES":{}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			reached, code := serveGraphQLBody(t, body)
			if reached {
				t.Errorf("an ambiguous body reached the origin (status %d)", code)
			}
			if code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", code, http.StatusBadRequest)
			}
		})
	}
}

// TestGraphQLFirewallStillPassesUnambiguousBodies keeps the fix from refusing
// ordinary requests, including nested objects that reuse a top-level name.
func TestGraphQLFirewallStillPassesUnambiguousBodies(t *testing.T) {
	bodies := []string{
		`{"query":"{ user }"}`,
		`{"query":"query A { user }","operationName":"A","variables":{"query":"x","Query":"y"}}`,
		`{"query":"{ user }","extensions":{"persistedQuery":{"version":1}}}`,
	}
	for _, body := range bodies {
		if reached, code := serveGraphQLBody(t, body); !reached {
			t.Errorf("%s: refused with %d, want forwarded", body, code)
		}
	}
}

func serveGraphQLBody(t *testing.T, body string) (bool, int) {
	t.Helper()
	mw, err := NewGraphQLFirewall(map[string]string{"introspection": "false"})
	if err != nil {
		t.Fatalf("NewGraphQLFirewall: %v", err)
	}
	var reached bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "http://x/graphql", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return reached, rec.Code
}

// TestGraphQLFirewallRefusesAmbiguousGETParams is the URL form of the same
// bypass: url.Values.Get returns the first of a repeated parameter, while
// Express passes an array, PHP keeps the last and ASP.NET Core matches names
// case-insensitively.
func TestGraphQLFirewallRefusesAmbiguousGETParams(t *testing.T) {
	const blocked = "%7B__schema%7Btypes%7Bname%7D%7D%7D"
	cases := map[string]string{
		"repeated query":     "query=%7Buser%7D&query=" + blocked,
		"case variant":       "query=%7Buser%7D&Query=" + blocked,
		"semicolon smuggle":  "a=1;query=" + blocked,
		"repeated variables": "query=%7Buser%7D&variables=%7B%7D&variables=%7B%7D",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			reached, code := serveGraphQLGET(t, raw)
			if reached || code != http.StatusBadRequest {
				t.Errorf("reached=%v status=%d, want refused with 400", reached, code)
			}
		})
	}
	if reached, code := serveGraphQLGET(t, "query=%7Buser%7D&operationName=A&page=1&page=2"); !reached {
		t.Errorf("an unambiguous GET was refused with %d", code)
	}
}

func serveGraphQLGET(t *testing.T, rawQuery string) (bool, int) {
	t.Helper()
	mw, err := NewGraphQLFirewall(map[string]string{"introspection": "false"})
	if err != nil {
		t.Fatalf("NewGraphQLFirewall: %v", err)
	}
	var reached bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/graphql?"+rawQuery, nil))
	return reached, rec.Code
}
