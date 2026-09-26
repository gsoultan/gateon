// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestHandlerJSONTagsUseTheDashboardsSpelling covers struct tags. A payload
// written as a map literal has no tags, and one got past it:
// POST /v1/auth/2fa/enroll answered qr_code_url and recovery_codes, and the login
// page reads qrCodeUrl and recoveryCodes, so an account made to enroll in 2FA saw
// a broken QR image and was never shown its recovery codes.

var snakeCaseKey = regexp.MustCompile(`^[a-z0-9]+_[a-z0-9_]*$`)

// snakeCaseMapKeysAllowed names, as "file:key", the snake_case keys handlers
// write in JSON map literals on purpose, each with the dashboard file that reads
// that spelling, or "" for a key the dashboard does not read at all. A named
// reader must still contain the key: those readers fall back to zero, so one that
// stopped reading this spelling would fail silently.
var snakeCaseMapKeysAllowed = map[string]string{
	// GET /v1/diag/agg-stats, which the dashboard reads through
	// aggStatsWire.ts, the adapter from this wire shape to its own names.
	"diagnostics.go:total_requests":        "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:total_errors":          "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:total_bandwidth_bytes": "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:active_connections":    "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:open_circuits":         "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:half_open_circuits":    "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:healthy_targets":       "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:total_targets":         "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:cpu_usage":             "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:memory_usage":          "ui/src/hooks/aggStatsWire.ts",
	"diagnostics.go:requests_per_second":   "",
	// GET /v1/diag/sys; useGateonStatus.ts falls back to this spelling.
	"diagnostics.go:uptime_seconds": "ui/src/hooks/useGateonStatus.ts",
	"diagnostics.go:memory_alloc":   "",
	// POST /v1/diag/test-target, which the dashboard does not call.
	"diagnostics.go:status_code": "",
	// POST /v1/config/import?dryRun=true echoes the flag back; unread.
	"config_import_export.go:dry_run": "",
}

type snakeCaseMapKey struct {
	key  string
	line int
}

// snakeCaseMapKeys lists the underscore keys file writes in map[string]any
// literals, which in this package are JSON payloads. A map[string]string is a
// middleware config, whose keys are snake_case by design and checked against
// the dashboard by make check-invariants. A literal whose type is elided inside
// another literal is not seen.
func snakeCaseMapKeys(fset *token.FileSet, file *ast.File) []snakeCaseMapKey {
	var found []snakeCaseMapKey
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if mt, ok := lit.Type.(*ast.MapType); !ok || !isEmptyInterface(mt.Value) {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			bl, ok := kv.Key.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				continue
			}
			if key, err := strconv.Unquote(bl.Value); err == nil && snakeCaseKey.MatchString(key) {
				found = append(found, snakeCaseMapKey{key: key, line: fset.Position(bl.Pos()).Line})
			}
		}
		return true
	})
	return found
}

func isEmptyInterface(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "any"
	case *ast.InterfaceType:
		return v.Methods == nil || len(v.Methods.List) == 0
	}
	return false
}

func TestHandlerJSONMapKeysUseTheDashboardsSpelling(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, k := range snakeCaseMapKeys(fset, file) {
			reader, ok := snakeCaseMapKeysAllowed[f+":"+k.key]
			if !ok {
				t.Errorf("%s:%d writes the JSON key %q.\n"+
					"    The dashboard reads protojson's lowerCamel, which never matches it. Spell it in\n"+
					"    lowerCamel, or name the dashboard code that reads this spelling in snakeCaseMapKeysAllowed.",
					f, k.line, k.key)
				continue
			}
			if reader == "" {
				continue
			}
			src, err := os.ReadFile(filepath.Join("..", "..", "..", reader)) // #nosec G304 -- a path from the table above
			if err != nil {
				t.Fatalf("read %s: %v", reader, err)
			}
			if !strings.Contains(string(src), k.key) {
				t.Errorf("%s:%d writes %q, and %s, named as its reader, no longer reads that spelling", f, k.line, k.key, reader)
			}
		}
	}
}

// The guard has to see the shape that shipped and leave config maps alone.
func TestSnakeCaseMapKeyGuardDetectsTheShapeItLooksFor(t *testing.T) {
	const src = `package p
var _ = map[string]any{"id": 1, "qr_code_url": 2, "qrCodeUrl": 3}
var _ = map[string]interface{}{"recovery_codes": 4}
var _ = map[string]string{"requests_per_minute": "100"}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var keys []string
	for _, k := range snakeCaseMapKeys(fset, file) {
		keys = append(keys, k.key)
	}
	if want := []string{"qr_code_url", "recovery_codes"}; !slices.Equal(keys, want) {
		t.Errorf("found %q, want %q", keys, want)
	}
}
