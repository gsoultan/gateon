// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command checkauthnil asserts that no auth.Service is compared against nil.
//
// A Holder is never nil but is unusable until Setup installs a real Manager, so
// `x == nil` answers "is the field populated" when the question is "can this
// authenticate a request". auth.Available asks the second one. Reading the first
// as the second is how the management API came to be served unauthenticated on a
// first run.
//
// check-security-invariants.sh has guarded this since that bypass, by grepping
// for `.AuthManager == nil` and three sibling spellings. On 2026-09-04 an
// instance turned up that the grep could not match:
//
//	func isLogsRequestAuthorized(r *http.Request, verifier middleware.TokenVerifier) bool {
//	    ...
//	    if verifier == nil {
//	        return true   // streams the system log to anyone
//	    }
//
// The service was passed as a parameter rather than read from a field, and named
// for the narrow interface it was typed as. Nothing about the spelling was
// unusual; the grep was simply matching names, and a name is not the property
// being checked.
//
// This resolves types instead, so a comparison is caught wherever the value came
// from -- field, parameter, local, or a call's result -- and under any name.
//
// Usage:
//
//	go run ./scripts/checkauthnil
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	authPkgPath = "github.com/gsoultan/gateon/internal/auth"
	serviceName = "Service"
)

// goosValues are analysed in turn because build tags decide which files exist,
// and a comparison inside a _linux.go file is invisible to a darwin load. This
// is the same reason `make staticcheck` runs both.
var goosValues = []string{"linux", "darwin"}

// exemptPkgs may compare a Service to nil: auth itself implements Available,
// whose entire job is to make that comparison correctly and once.
var exemptPkgs = map[string]bool{
	authPkgPath: true,
}

type finding struct {
	pos  string
	expr string
}

// isAuthService reports whether t is exactly auth.Service. Implementations of
// it are not flagged: a concrete *Manager compared to nil is an ordinary nil
// check, and it is the interface that carries the Holder trap.
func isAuthService(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Name() != serviceName || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == authPkgPath
}

// nilComparison returns the non-nil operand of a `x == nil` or `x != nil`
// comparison, or nil if the expression is not one.
func nilComparison(bin *ast.BinaryExpr, info *types.Info) ast.Expr {
	if bin.Op != token.EQL && bin.Op != token.NEQ {
		return nil
	}
	isNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "nil" && info.Uses[id] != nil &&
			info.Uses[id].Type() == types.Typ[types.UntypedNil]
	}
	switch {
	case isNil(bin.Y):
		return bin.X
	case isNil(bin.X):
		return bin.Y
	}
	return nil
}

func scan(pkg *packages.Package, seen map[string]finding) {
	if exemptPkgs[pkg.PkgPath] || strings.HasSuffix(pkg.PkgPath, ".test") {
		return
	}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			operand := nilComparison(bin, pkg.TypesInfo)
			if operand == nil {
				return true
			}
			if !isAuthService(pkg.TypesInfo.TypeOf(operand)) {
				return true
			}
			pos := pkg.Fset.Position(bin.Pos()).String()
			// Keyed by position so the two GOOS passes report a shared file once.
			seen[pos] = finding{pos: pos, expr: types.ExprString(bin)}
			return true
		})
	}
}

// run analyses the given package patterns and returns every nil-comparison on
// an auth.Service, sorted by position. Separated from main so a test can point
// it at a fixture rather than at the whole tree.
func run(patterns ...string) ([]finding, error) {
	seen := make(map[string]finding)
	for _, goos := range goosValues {
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
				packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
			Env:   append(os.Environ(), "GOOS="+goos),
			Tests: true,
		}
		pkgs, err := packages.Load(cfg, patterns...)
		if err != nil {
			return nil, fmt.Errorf("loading packages for GOOS=%s: %w", goos, err)
		}
		// Load errors are not fatal on their own: a package that fails to type
		// check under one GOOS is usually one whose generated code is absent,
		// and the other pass still covers the hand-written files.
		for _, pkg := range pkgs {
			scan(pkg, seen)
		}
	}

	out := make([]finding, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out, nil
}

func main() {
	out, err := run("./...")
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkauthnil: %v\n", err)
		os.Exit(2)
	}

	if len(out) == 0 {
		fmt.Println("checkauthnil: ok - no auth.Service compared against nil")
		return
	}

	fmt.Fprintf(os.Stderr, "checkauthnil: %d auth.Service nil-comparison(s)\n\n", len(out))
	for _, f := range out {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", f.pos, f.expr)
	}
	fmt.Fprintf(os.Stderr, `
An auth.Holder is never nil but cannot authenticate until Setup has installed a
real Manager, so this comparison answers "is the field populated" when the
question is "can this authenticate a request". Use auth.Available(x), which
denies for a nil service and for a Holder that is not ready.
`)
	os.Exit(1)
}
