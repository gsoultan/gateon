// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package apischema

import (
	"errors"
	"strings"
	"testing"
)

const ordersDoc = `
openapi: 3.0.3
info: {title: Orders, version: "1"}
paths:
  /api/v1/orders:
    get:
      parameters:
        - {name: id, in: query, schema: {type: integer}}
        - {name: status, in: query, schema: {type: string, enum: [pending, shipped]}}
        - {name: note, in: query, schema: {type: string, maxLength: 200}}
`

func TestCompileReportsWhatTheDocumentConstrains(t *testing.T) {
	s, rep, err := Compile(ordersDoc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, ok := s.Lookup("GET", "/api/v1/orders"); !ok {
		t.Error("the compiled schema does not describe GET /api/v1/orders")
	}
	if rep.Operations != 1 || rep.Fields != 3 || rep.Inert != 2 {
		t.Errorf("report = %+v, want 1 operation, 3 constrained fields, 2 inert", rep)
	}
}

func TestCompileAcceptsJSON(t *testing.T) {
	doc := `{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/a":{"get":{"parameters":[{"name":"n","in":"query","schema":{"type":"integer"}}]}}}}`
	if _, rep, err := Compile(doc); err != nil || rep.Operations != 1 {
		t.Errorf("Compile(JSON) = %+v, %v", rep, err)
	}
}

// TestCompileRefusesWhatWouldCheckNothing: each of these would otherwise load
// and leave a route showing a document that constrains no request.
func TestCompileRefusesWhatWouldCheckNothing(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want error
	}{
		{"not a document", "hello: world\n", errNotOpenAPI},
		{"swagger 2", "swagger: \"2.0\"\npaths: {}\n", errNotOpenAPI},
		{"no paths", "openapi: 3.0.3\ninfo: {title: x, version: \"1\"}\npaths: {}\n", ErrNoPaths},
		{"not yaml", "openapi: [3.0\n  paths", errUnusable},
		{"too large", "openapi: 3.0.3\n#" + strings.Repeat("x", MaxDocumentBytes), ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _, err := Compile(tt.doc)
			if !errors.Is(err, tt.want) {
				t.Errorf("Compile error = %v, want %v", err, tt.want)
			}
			if s != nil {
				t.Error("a schema was returned beside an error")
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": Record, "record": Record, " Record ": Record, "enforce": Enforce, "ENFORCE": Enforce} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// A near miss in either direction is refused: "enforced" read as record
	// leaves an operator believing requests are refused.
	for _, in := range []string{"enforced", "block", "on", "true"} {
		if _, err := ParseMode(in); !errors.Is(err, ErrUnknownMode) {
			t.Errorf("ParseMode(%q) error = %v, want ErrUnknownMode", in, err)
		}
	}
	if Record.String() != ModeRecord || Enforce.String() != ModeEnforce {
		t.Errorf("String() = %q, %q", Record, Enforce)
	}
}
