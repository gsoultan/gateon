// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
// Limits: keys are matched by name, not by middleware type (a key two
// editors share is covered by one row); keys are found by the literal first
// argument of updateConfig(...) or toggle(...), so a key built at run time is
// not seen; and global settings (the proto *Config messages the settings page
// writes) have no rows yet -- the dead-field and dead-sink checks are what
// cover them.

const (
	effectsRegistryPath = "internal/middleware/dashboard_key_effects_test.go"
	effectsBaselinePath = "scripts/checkconfig/effects-baseline.txt"
	editorsDir          = "ui/src/components/MiddlewareConfig"
)

// dashboardKeyRE finds the key in updateConfig("key", ...) and toggle("key",
// ...), the two ways the editors write one, across line breaks.
var dashboardKeyRE = regexp.MustCompile(`\b(?:updateConfig|toggle)\(\s*"([A-Za-z0-9_]+)"`)

// effectRows reads the registry: every key with a row, and whether the row
// says the key is (still) inert.
func effectRows(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	rows := map[string]bool{} // key -> inert
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		fields := literalFields(lit)
		if key, ok := fields["key"]; ok {
			_, inert := fields["inert"]
			rows[key] = rows[key] || inert
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

// dashboardKeys lists every key the middleware editors write.
func dashboardKeys(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".tsx") || strings.HasSuffix(name, ".test.tsx") {
			continue
		}
		// #nosec G304 -- a build-time developer command; dir is the editorsDir
		// constant or a t.TempDir() fixture, name comes from ReadDir of it.
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		for _, m := range dashboardKeyRE.FindAllStringSubmatch(string(src), -1) {
			keys[m[1]] = true
		}
	}
	return keys, nil
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
// baseline line.
func checkEffects() bool {
	ui, err := dashboardKeys(editorsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading the dashboard editors: %v\n", err)
		os.Exit(2)
	}
	rows, err := effectRows(effectsRegistryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading the effect registry: %v\n", err)
		os.Exit(2)
	}
	baseline, err := loadBaseline(effectsBaselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading the effects baseline: %v\n", err)
		os.Exit(2)
	}
	r := compareEffects(ui, rows, baseline)
	for _, k := range r.staleBaseline {
		fmt.Printf("  note - %s has an effect row or is no longer written; delete it from %s\n", k, effectsBaselinePath)
	}
	if len(r.uncovered) == 0 {
		fmt.Printf("ok - %d dashboard middleware keys: %d proven by an effect test, %d known inert, %d baselined\n",
			len(ui), r.proven, r.inert, r.baselined)
		return false
	}
	fmt.Fprintf(os.Stderr, "\ndashboard middleware keys with no effect test:\n")
	for _, k := range r.uncovered {
		fmt.Fprintf(os.Stderr, "  %s\n", k)
	}
	fmt.Fprintf(os.Stderr, `
A setting the dashboard writes needs a row in %s that
changes it and shows the gateway answering differently -- or, until it has one,
a line in %s saying why.
`, effectsRegistryPath, effectsBaselinePath)
	return true
}
