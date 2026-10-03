// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// sinkFixture is a middleware-shaped package: a config map read into a struct,
// one field of which is consulted. It is the shape of T21 (XFCC ForwardBy).
const sinkFixture = `package fix

type Config struct {
	Used, Stored bool
	Assigned     int
}

func build(cfg map[string]string) Config {
	c := Config{Used: cfg["used"] == "true", Stored: cfg["stored"] == "true"}
	c.Assigned = len(cfg["assigned"])
	return c
}

func serve(c Config) bool { return c.Used }
`

// checkFixture type-checks src as package path and returns its sink facts.
func checkFixture(t *testing.T, path, src string) *sinkFacts {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fix.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{},
		Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	if _, err := (&types.Config{Importer: importer.Default()}).Check(path, fset, []*ast.File{file}, info); err != nil {
		t.Fatal(err)
	}
	facts := newSinkFacts()
	recordSinks(fset, file, info, facts)
	return facts
}

func TestDeadSinksAreTheConfigFedFieldsNothingReads(t *testing.T) {
	dead := checkFixture(t, modulePath+"/internal/fix", sinkFixture).deadSinks()
	var names []string
	for name := range dead {
		names = append(names, name)
	}
	slices.Sort(names)
	want := []string{"fix.Config.Assigned", "fix.Config.Stored"}
	if !slices.Equal(names, want) {
		t.Fatalf("dead sinks = %v, want %v (Used is read by serve)", names, want)
	}
}

// A json-tagged field of a management API response is read by encoding/json,
// so it is not a dead sink; the same field outside the transport packages is.
func TestAResponseFieldIsReadByItsEncoder(t *testing.T) {
	const src = `package handlers

type Report struct {
	Enabled bool ` + "`json:\"enabled\"`" + `
}

func report(cfg map[string]string) Report { return Report{Enabled: cfg["on"] == "true"} }
`
	if dead := checkFixture(t, modulePath+"/internal/server/handlers", src).deadSinks(); len(dead) != 0 {
		t.Fatalf("a response field was reported dead: %v", dead)
	}
	if dead := checkFixture(t, modulePath+"/internal/fix", src).deadSinks(); len(dead) != 1 {
		t.Fatalf("a json-tagged config field outside the transport was not reported: %v", dead)
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The editors write a key through updateConfig or toggle, sometimes on the
// line after the call; a test file's keys are not the dashboard's.
func TestDashboardKeysFindsEveryWayAKeyIsWritten(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Editor.tsx", `
		updateConfig("one_line", v);
		updateConfig(
		  "next_line", v);
		toggle("toggled", e.currentTarget.checked);
	`)
	writeFile(t, dir, "Editor.test.tsx", `updateConfig("from_a_test", v);`)
	keys, err := dashboardKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"one_line", "next_line", "toggled"} {
		if !keys[k] {
			t.Errorf("key %q not found", k)
		}
	}
	if keys["from_a_test"] {
		t.Error("a key from a test file was counted")
	}
}

func TestEffectRowsAndTheComparison(t *testing.T) {
	path := writeFile(t, t.TempDir(), "effects_test.go", `package m
var rows = []keyEffect{
	{mwType: "waf", key: "proven", a: "1", b: "2"},
	{mwType: "waf", key: "still_inert", a: "1", b: "2", inert: "T8"},
}`)
	rows, err := effectRows(path)
	if err != nil {
		t.Fatal(err)
	}
	if inert, ok := rows["proven"]; !ok || inert {
		t.Fatalf("rows = %v, want proven with no inert mark", rows)
	}
	if !rows["still_inert"] {
		t.Fatalf("rows = %v, want still_inert marked inert", rows)
	}

	ui := map[string]bool{"proven": true, "still_inert": true, "baselined": true, "new_switch": true}
	baseline := map[string]bool{"baselined": true, "proven": true, "removed_from_ui": true}
	r := compareEffects(ui, rows, baseline)
	if !slices.Equal(r.uncovered, []string{"new_switch"}) {
		t.Errorf("uncovered = %v, want the new switch alone", r.uncovered)
	}
	if !slices.Equal(r.staleBaseline, []string{"proven", "removed_from_ui"}) {
		t.Errorf("stale baseline = %v, want the key with a row and the key the dashboard dropped", r.staleBaseline)
	}
	if r.proven != 1 || r.inert != 1 || r.baselined != 1 {
		t.Errorf("proven %d, inert %d, baselined %d; want 1 each", r.proven, r.inert, r.baselined)
	}
}
