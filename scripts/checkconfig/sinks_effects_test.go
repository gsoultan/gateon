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

// editorFixture is a dispatcher and two editor files, in the shapes the
// dashboard uses: an inline arm, an arm rendering a component that renders
// another, fallthrough labels with a camelCase alias, and a component no arm
// renders.
func editorFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "MiddlewareConfigEditor.tsx", `
export function MiddlewareConfigEditor({ type }) {
  switch (type) {
    case "cors":
      return <CorsEditor />;
    case "grpcweb":
      return (<Stack>{updateConfig(
        "allowed_origins", v)}</Stack>);
    case "file_security":
    case "fileSecurity":
      return <Shared />;
    default:
      return <Text>Unknown middleware type</Text>;
  }
}
`)
	writeFile(t, dir, "Editors.tsx", `
export function CorsEditor() {
  updateConfig("allowed_origins", v);
  toggle("allow_credentials", e.currentTarget.checked);
}

export function Shared() {
  return <Inner />;
}

function Inner() {
  updateConfig("deep", v);
}

export function Unrendered() {
  updateConfig("orphan", v);
}
`)
	writeFile(t, dir, "Editors.test.tsx", `updateConfig("from_a_test", v);`)
	return dir
}

// TestDashboardKeysAreAttributedToTheTypeThatWritesThem is truth NEW-10: the
// gate matched keys by name, so the cors row proving allowed_origins counted
// for grpcweb too. Each key now belongs to the type whose editor writes it.
func TestDashboardKeysAreAttributedToTheTypeThatWritesThem(t *testing.T) {
	keys, orphans, err := dashboardTypeKeys(editorFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cors/allow_credentials", "cors/allowed_origins", "file_security/deep", "grpcweb/allowed_origins"}
	var got []string
	for k := range keys {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
	if !slices.Equal(orphans, []string{"orphan"}) {
		t.Errorf("orphans = %v, want the key only an unrendered editor writes", orphans)
	}
}

func TestEffectRowsAndTheComparison(t *testing.T) {
	path := writeFile(t, t.TempDir(), "effects_test.go", `package m
var rows = []keyEffect{
	{mwType: "cors", key: "allowed_origins", a: "1", b: "2"},
	{mwType: "waf", key: "still_inert", a: "1", b: "2", inert: "T8"},
}`)
	rows, err := effectRows(path)
	if err != nil {
		t.Fatal(err)
	}
	if inert, ok := rows["cors/allowed_origins"]; !ok || inert {
		t.Fatalf("rows = %v, want cors/allowed_origins with no inert mark", rows)
	}
	if !rows["waf/still_inert"] {
		t.Fatalf("rows = %v, want waf/still_inert marked inert", rows)
	}

	ui := map[string]bool{"cors/allowed_origins": true, "grpcweb/allowed_origins": true, "waf/still_inert": true,
		"waf/baselined": true}
	baseline := map[string]bool{"waf/baselined": true, "cors/allowed_origins": true, "waf/removed_from_ui": true}
	r := compareEffects(ui, rows, baseline)
	// The cors row does not prove grpcweb's key of the same name.
	if !slices.Equal(r.uncovered, []string{"grpcweb/allowed_origins"}) {
		t.Errorf("uncovered = %v, want grpcweb's allowed_origins alone", r.uncovered)
	}
	if !slices.Equal(r.staleBaseline, []string{"cors/allowed_origins", "waf/removed_from_ui"}) {
		t.Errorf("stale baseline = %v, want the key with a row and the key the dashboard dropped", r.staleBaseline)
	}
	if r.proven != 1 || r.inert != 1 || r.baselined != 1 {
		t.Errorf("proven %d, inert %d, baselined %d; want 1 each", r.proven, r.inert, r.baselined)
	}
}

// TestABaselineNoteMustCiteAFactoryLevelTest is the rest of NEW-10: notes
// for window_size, error_threshold and min_requests cited tests that build
// the breaker's config struct directly, which pass whatever the factory does
// with the key. A cited test must reach the factory (directly or through a
// helper in its package); otherwise the note must say unproven.
func TestABaselineNoteMustCiteAFactoryLevelTest(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "mw")
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkg, "x_test.go", `package mw
func build() { NewFactory(nil).Create(nil, "r") }
func TestDirect(t *testing.T) { _ = CircuitBreaker(CircuitBreakerConfig{WindowSize: 1}) }
func TestViaFactory(t *testing.T) { NewFactory(nil).Create(nil, "r") }
func TestViaHelper(t *testing.T) { build() }
`)
	idx, err := indexTests(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{ // note -> holds
		"unproven: time-based":                    true,
		"INERT T8":                                true,
		"proven by TestViaFactory":                true,
		"proven by TestViaHelper, TestViaFactory": true,
		"proven by TestDirect":                    false,
		"proven by TestNoSuchTest":                false,
		"":                                        false,
		"time-based; see TestViaFactory":          false,
	}
	for note, holds := range cases {
		if got := noteProblem(note, idx) == ""; got != holds {
			t.Errorf("note %q: holds = %v, want %v (%s)", note, got, holds, noteProblem(note, idx))
		}
	}
}

// TestThePickerMustOfferEveryFactoryType is T36 / NEW-8 at the gate: the
// picker's list fell ten types behind the factory and nothing noticed.
func TestThePickerMustOfferEveryFactoryType(t *testing.T) {
	factory, err := factoryTypes(`func (f *Factory) Create() {
	switch m.Type {
	case "ratelimit":
		return x
	case "bot_management":
		return y
	case "xss_recognition", "sqli_recognition":
		return z
	default:
		return nil
	}
}`)
	if err != nil {
		t.Fatal(err)
	}
	picker := pickerTypes(`[{ label: "Rate Limiting", value: "ratelimit" }, { label: "X", value: "xss_recognition" }, { label: "Old", value: "retired" }]`)
	missing, unknown := comparePicker(factory, picker)
	if !slices.Equal(missing, []string{"bot_management", "sqli_recognition"}) {
		t.Errorf("missing = %v, want the two the picker leaves out", missing)
	}
	if !slices.Equal(unknown, []string{"retired"}) {
		t.Errorf("unknown = %v, want the value the factory does not build", unknown)
	}
}

// TestGlobalSecuritySettingsNeedARowOrANote: a global security threshold read
// and then ignored passed every gate, because global settings had no rows.
func TestGlobalSecuritySettingsNeedARowOrANote(t *testing.T) {
	path := writeFile(t, t.TempDir(), "global_test.go", `package r
var rows = []globalEffect{{field: "security_advanced.pow.score_threshold", a: "1", b: "2"}}`)
	rows, err := globalRows(path)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{"security_advanced.pow.score_threshold", "security_advanced.entropy.threshold",
		"security_advanced.ip_reputation.block_threshold"}
	missing := compareGlobals(required, rows, map[string]string{"security_advanced.entropy.threshold": "unproven: x"})
	if !slices.Equal(missing, []string{"security_advanced.ip_reputation.block_threshold"}) {
		t.Errorf("missing = %v, want the setting with neither a row nor a line", missing)
	}
}
