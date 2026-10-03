// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"
)

func TestDocumentedValuesAreTheClosedLists(t *testing.T) {
	body := `
  string action = 6; // "notify", "block", "challenge"
  string resource = 1; // "routes", "services", etc.
  string address = 3; // e.g., ":80", "0.0.0.0:443"
  string single = 4; // "only"
  bool flag = 5; // "true", "false"
`
	got := documentedIn("AlertPlaybook", body)
	if len(got) != 1 || got[0].Field != "action" || !slices.Equal(got[0].values, []string{"notify", "block", "challenge"}) {
		t.Fatalf("documented = %+v, want only action with its three values (an open list, examples, "+
			"a single value and a non-string field are not checked)", got)
	}
	if documentedIn("QueryTracesRequest", body) != nil {
		t.Fatal("a wire message's values were checked")
	}
}

// playbookFixture is a package laid out as the alerting manager reads a
// playbook: the field compared against "block" only. It is checked as the
// generated proto package itself, so the playbook is a proto type.
const playbookFixture = `package v1

type AlertPlaybook struct{ Action string }

const blockAction = "block"

func run(pb *AlertPlaybook) bool { return pb.Action == blockAction }

func level(s string) int {
	switch s {
	case "TLS1.2":
		return 2
	}
	return 0
}
`

func TestValuesHandledAreTheOnesComparedWhereTheFieldIsRead(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fix.go", playbookFixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	if _, err := (&types.Config{Importer: importer.Default()}).Check(protoPkgPath, fset, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	facts := newValueFacts()
	recordValues(protoPkgPath, file, info, facts)
	action := documentedField{protoField: protoField{Message: "AlertPlaybook", Field: "action", Accessor: "Action"}}
	if !facts.handled(action, "block") {
		t.Error(`"block" is compared (through a constant) and was not seen`)
	}
	if facts.handled(action, "challenge") {
		t.Error(`"challenge" is compared nowhere and was reported handled -- the T38 shape`)
	}
	other := documentedField{protoField: protoField{Message: "Elsewhere", Field: "x", Accessor: "X"}}
	if facts.handled(other, "block") {
		t.Error("a value compared in a package that does not read the field counted for it")
	}
	if fold("TLS_1.2") != fold("tls12") {
		t.Error("fold does not equate the spellings code folds")
	}
}
