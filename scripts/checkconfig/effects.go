// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
)

// The effect registry check (ADR 0048).
//
// The two checks above prove a setting is read. Neither can prove it does
// anything: T8's WAF category switches are read, stored and consulted, and
// still change nothing, because the rules they remove are not the rules that
// match. The only proof is behavioural -- flip the key, watch the response --
// which is what internal/middleware/dashboard_key_effects_test.go does, one
// row per key, through the factory the router uses.
//
// This check keeps that registry honest from the other side: every key the
// dashboard's middleware editors write must have a row there, or a line in
// effects-baseline.txt saying why not yet. A new switch in the dashboard
// therefore arrives with a test that shows it working, or with its absence
// written down.
//
// Keys are matched by (middleware type, key): a row proves a key for the type
// whose factory it builds, and nothing else (truth NEW-10 -- cors's
// allowed_origins row counted for grpcweb, which ignored the key). A baseline
// note is held to what it claims (notes.go). Keys are found by the literal
// first argument of updateConfig(...) or toggle(...), so a key built at run
// time is not seen. The security switches among the global settings have
// their own registry (globals.go).

const (
	effectsRegistryPath = "internal/middleware/dashboard_key_effects_test.go"
	effectsBaselinePath = "scripts/checkconfig/effects-baseline.txt"
	editorsDir          = "ui/src/components/MiddlewareConfig"
)

// dashboardKeyRE finds the key in updateConfig("key", ...) and toggle("key",
// ...), the two ways the editors write one, across line breaks.
var dashboardKeyRE = regexp.MustCompile(`\b(?:updateConfig|toggle)\(\s*"([A-Za-z0-9_]+)"`)

// effectRows reads the registry: every "type/key" with a row, and whether the
// row says the key is (still) inert.
func effectRows(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	rows := map[string]bool{} // "type/key" -> inert
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		fields := literalFields(lit)
		key, hasKey := fields["key"]
		typ, hasType := fields["mwType"]
		if hasKey && hasType {
			_, inert := fields["inert"]
			k := typedKey(typ, key)
			rows[k] = rows[k] || inert
		}
		return true
	})
	return rows, nil
}

// literalFields returns a composite literal's string-literal fields by name.
func literalFields(lit *ast.CompositeLit) map[string]string {
	out := map[string]string{}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if v, ok := kv.Value.(*ast.BasicLit); ok && v.Kind == token.STRING {
			if s, err := strconv.Unquote(v.Value); err == nil {
				out[name.Name] = s
			}
		}
	}
	return out
}

// effectsReport is what the check concluded.
type effectsReport struct {
	uncovered, staleBaseline []string
	proven, inert, baselined int
}

func compareEffects(ui, rows, baseline map[string]bool) effectsReport {
	var r effectsReport
	for key := range ui {
		inert, hasRow := rows[key]
		switch {
		case hasRow && inert:
			r.inert++
		case hasRow:
			r.proven++
		case baseline[key]:
			r.baselined++
		default:
			r.uncovered = append(r.uncovered, key)
		}
	}
	for key := range baseline {
		if _, hasRow := rows[key]; hasRow || !ui[key] {
			r.staleBaseline = append(r.staleBaseline, key)
		}
	}
	sort.Strings(r.uncovered)
	sort.Strings(r.staleBaseline)
	return r
}

// checkEffects runs the check; true when a dashboard key has no row and no
// baseline line, when an editor writes a key no type renders, or when a
// baseline note claims what it cannot show.
func checkEffects(idx testIndex) bool {
	ui, orphans, err := dashboardTypeKeys(editorsDir)
	if err != nil {
		fatalf("reading the dashboard editors: %v", err)
	}
	rows, err := effectRows(effectsRegistryPath)
	if err != nil {
		fatalf("reading the effect registry: %v", err)
	}
	notes, err := loadNotedBaseline(effectsBaselinePath)
	if err != nil {
		fatalf("reading the effects baseline: %v", err)
	}
	baseline := map[string]bool{}
	for k := range notes {
		baseline[k] = true
	}
	r := compareEffects(ui, rows, baseline)
	for _, k := range r.staleBaseline {
		fmt.Printf("  note - %s has an effect row or is no longer written; delete it from %s\n", k, effectsBaselinePath)
	}
	failed := reportList(orphans, "dashboard keys written by an editor no middleware type renders",
		"Render the editor from MiddlewareConfigEditor's switch, or remove the key.")
	failed = reportNotes(notes, idx) || failed
	if len(r.uncovered) == 0 {
		fmt.Printf("ok - %d dashboard (type, key) pairs: %d proven by an effect test, %d known inert, %d baselined\n",
			len(ui), r.proven, r.inert, r.baselined)
		return failed
	}
	reportList(r.uncovered, "dashboard middleware keys with no effect test (type/key)", fmt.Sprintf(
		`A setting the dashboard writes needs a row in %s that
changes it and shows the gateway answering differently -- or, until it has one,
a line in %s saying why.`, effectsRegistryPath, effectsBaselinePath))
	return true
}

// reportNotes fails on a baseline note that claims what it cannot show.
func reportNotes(notes map[string]string, idx testIndex) bool {
	var bad []string
	for k, note := range notes {
		if p := noteProblem(note, idx); p != "" {
			bad = append(bad, k+": "+p)
		}
	}
	sort.Strings(bad)
	return reportList(bad, "effects-baseline notes that do not hold", "")
}

// reportList prints a titled failure list; true when there is one.
func reportList(items []string, title, advice string) bool {
	if len(items) == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "\n%s:\n", title)
	for _, it := range items {
		fmt.Fprintf(os.Stderr, "  %s\n", it)
	}
	if advice != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", advice)
	}
	return true
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "checkconfig: "+format+"\n", args...)
	os.Exit(2)
}
