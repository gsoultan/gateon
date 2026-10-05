// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// What an effects-baseline note may say (truth NEW-10).
//
// A baseline line is a key the registry has not proven. Its note used to be
// free text, and three of them cited tests that build the circuit breaker's
// config struct directly: a factory that dropped window_size would pass every
// one of them, so the note read as proof and proved nothing. A note now says
// one of three things, and the check holds it to it:
//
//   - "unproven: <why>" -- the honest default;
//   - "INERT <finding>" -- a key a finding says does nothing;
//   - "proven by TestX[, TestY]" -- tests that exist and build the middleware
//     through the factory the router uses (they call NewFactory or
//     ApplyRouteMiddlewares, directly or through a helper in their package).

var testNameRE = regexp.MustCompile(`\bTest\w+`)

// factoryEntrypoints are the calls that build a middleware the way the router
// does.
var factoryEntrypoints = map[string]bool{"NewFactory": true, "ApplyRouteMiddlewares": true}

// loadNotedBaseline reads "key # note" lines into key -> note.
func loadNotedBaseline(path string) (map[string]string, error) {
	out := map[string]string{}
	// #nosec G304 -- effectsBaselinePath in the only non-test caller, a fixture
	// under t.TempDir() in the tests.
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, note, _ := strings.Cut(line, "#")
		if key = strings.TrimSpace(key); key != "" {
			out[key] = strings.TrimSpace(note)
		}
	}
	return out, nil
}

// testIndex knows every Test function under a tree and which of them reach
// the factory.
type testIndex struct {
	exists, factory map[string]bool
}

// indexTests parses every _test.go file under root.
func indexTests(root string) (testIndex, error) {
	idx := testIndex{exists: map[string]bool{}, factory: map[string]bool{}}
	byDir := map[string][]*ast.FuncDecl{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil // a file the toolchain would reject fails the build, not this check
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], fn)
			}
		}
		return nil
	})
	for _, fns := range byDir {
		indexPackage(fns, idx)
	}
	return idx, err
}

// indexPackage marks the tests of one package, following one hop into the
// package's own helpers.
func indexPackage(fns []*ast.FuncDecl, idx testIndex) {
	helpers := map[string]bool{}
	for _, fn := range fns {
		if callsAny(fn.Body, factoryEntrypoints) {
			helpers[fn.Name.Name] = true
		}
	}
	for _, fn := range fns {
		name := fn.Name.Name
		if !strings.HasPrefix(name, "Test") {
			continue
		}
		idx.exists[name] = true
		if helpers[name] || callsAny(fn.Body, helpers) {
			idx.factory[name] = true
		}
	}
}

// callsAny reports whether body calls a function or method named in names.
func callsAny(body ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			found = names[fun.Name]
		case *ast.SelectorExpr:
			found = names[fun.Sel.Name]
		}
		return !found
	})
	return found
}

// noteProblem says what is wrong with a baseline note, or "".
func noteProblem(note string, idx testIndex) string {
	switch {
	case strings.HasPrefix(note, "unproven"), strings.HasPrefix(note, "INERT"):
		return ""
	case note == "":
		return `has no note: say "unproven: <why>", "INERT <finding>", or "proven by TestX"`
	}
	tests := testNameRE.FindAllString(note, -1)
	if !strings.HasPrefix(note, "proven by") || len(tests) == 0 {
		return `note must start "unproven:", "INERT" or "proven by TestX"`
	}
	var bad []string
	for _, name := range tests {
		switch {
		case !idx.exists[name]:
			bad = append(bad, name+" (no such test)")
		case !idx.factory[name]:
			bad = append(bad, name+" (does not build through the factory)")
		}
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	return fmt.Sprintf("cites %s; cite a factory-level test or say unproven", strings.Join(bad, ", "))
}
