// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The documented-values check (ADR 0048).
//
// A string setting with a fixed set of choices -- `string action = 6; //
// "notify", "block", "challenge"` -- is read, so the field checks pass, while
// one of its choices may be handled by nothing: an alert playbook set to
// "Trigger JS Challenge" was saved, displayed, and did exactly what "Notify
// Only" does. So each value a proto field's comment lists must be compared
// against, in some package that reads that field: an == / != against the
// literal (or a string constant), or a case clause naming it. Values are
// compared folded (lower case, no '_', '-', '.' or space), as the code that
// reads them often folds them.
//
// A package also counts as reading the field when the field is passed straight
// to one of its functions (gtls.ParseTLSVersion(cfg.GetMinTlsVersion(), ...)
// compares the versions in package tls).
//
// Limits: a list ending in "etc." is open and not checked, nor are example
// values (anything with ':', '/', ',' or a space -- addresses, URLs), nor the
// wire messages (*Request, *Response, *Payload), whose values are not settings;
// a value handled through a map lookup, or more than one call away, is not seen
// and belongs in values-baseline.txt with a note.

const valuesBaselinePath = "scripts/checkconfig/values-baseline.txt"

var (
	anyMessageRE  = regexp.MustCompile(`(?s)message\s+(\w+)\s*\{(.*?)\n\}`)
	documentedRE  = regexp.MustCompile(`(?m)^\s*(?:optional\s+)?string\s+(\w+)\s*=\s*\d+\s*(?:\[[^\]]*\])?\s*;\s*//\s*(.*)$`)
	quotedValueRE = regexp.MustCompile(`"([^"]+)"`)
)

// documentedField is a string field whose comment lists its values.
type documentedField struct {
	protoField
	values []string
}

// collectDocumentedValues finds every string field whose trailing comment
// lists two or more quoted values and does not leave the list open.
func collectDocumentedValues(dir string) ([]documentedField, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []documentedField
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		// #nosec G304 -- as collectFields: protoDir or a test fixture.
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, m := range anyMessageRE.FindAllStringSubmatch(string(raw), -1) {
			out = append(out, documentedIn(m[1], m[2])...)
		}
	}
	return out, nil
}

func documentedIn(message, body string) []documentedField {
	for _, wire := range []string{"Request", "Response", "Payload"} {
		if strings.HasSuffix(message, wire) {
			return nil
		}
	}
	var out []documentedField
	for _, f := range documentedRE.FindAllStringSubmatch(body, -1) {
		comment := f[2]
		if strings.Contains(strings.ToLower(comment), "etc") {
			continue
		}
		var values []string
		for _, v := range quotedValueRE.FindAllStringSubmatch(comment, -1) {
			if !strings.ContainsAny(v[1], ":/, ") {
				values = append(values, v[1])
			}
		}
		if len(values) >= 2 {
			out = append(out, documentedField{
				protoField: protoField{Message: message, Field: f[1], Accessor: goName(f[1])},
				values:     values,
			})
		}
	}
	return out
}

// fold is the comparison form of a value.
func fold(s string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(s))
}

// valueFacts records, per package, the proto fields it selects and the string
// literals it compares against.
type valueFacts struct {
	selects  map[string]map[string]bool // pkg -> "Message.Name"
	compares map[string]map[string]bool // pkg -> folded literal
}

func newValueFacts() *valueFacts {
	return &valueFacts{selects: map[string]map[string]bool{}, compares: map[string]map[string]bool{}}
}

func (v *valueFacts) add(m map[string]map[string]bool, pkg, key string) {
	if m[pkg] == nil {
		m[pkg] = map[string]bool{}
	}
	m[pkg][key] = true
}

// recordValues walks one file of package pkg.
func recordValues(pkg string, file *ast.File, info *types.Info, facts *valueFacts) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if name := protoTypeName(info.TypeOf(x.X)); name != "" {
				facts.add(facts.selects, pkg, name+"."+x.Sel.Name)
			}
		case *ast.CallExpr:
			facts.addPassed(x, info)
		case *ast.BinaryExpr:
			if x.Op == token.EQL || x.Op == token.NEQ {
				facts.addLiteral(pkg, x.X, info)
				facts.addLiteral(pkg, x.Y, info)
			}
		case *ast.CaseClause:
			for _, e := range x.List {
				facts.addLiteral(pkg, e, info)
			}
		}
		return true
	})
}

// addPassed credits the package of a called function with reading any proto
// field passed to it directly, by field or by getter.
func (v *valueFacts) addPassed(call *ast.CallExpr, info *types.Info) {
	callee := calleeFunc(call, info)
	if callee == nil || callee.Pkg() == nil || !strings.HasPrefix(callee.Pkg().Path(), modulePath+"/") {
		return
	}
	for _, arg := range call.Args {
		if inner, ok := arg.(*ast.CallExpr); ok && len(inner.Args) == 0 {
			arg = inner.Fun // cfg.GetField()
		}
		sel, ok := arg.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if name := protoTypeName(info.TypeOf(sel.X)); name != "" {
			v.add(v.selects, callee.Pkg().Path(), name+"."+sel.Sel.Name)
		}
	}
}

// calleeFunc is the function a call statically names, if any.
func calleeFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	var id *ast.Ident
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		id = fn
	case *ast.SelectorExpr:
		id = fn.Sel
	default:
		return nil
	}
	f, _ := info.Uses[id].(*types.Func)
	return f
}

// addLiteral records e when it is a string literal or a string constant.
func (v *valueFacts) addLiteral(pkg string, e ast.Expr, info *types.Info) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return
	}
	v.add(v.compares, pkg, fold(constant.StringVal(tv.Value)))
}

// handled reports whether some package that reads f compares against value.
func (v *valueFacts) handled(f documentedField, value string) bool {
	for pkg, sel := range v.selects {
		if (sel[f.Message+"."+f.Accessor] || sel[f.Message+".Get"+f.Accessor]) && v.compares[pkg][fold(value)] {
			return true
		}
	}
	return false
}

// checkValues reports documented values nothing handles; true when one is new.
func checkValues(facts *valueFacts) bool {
	fields, err := collectDocumentedValues(protoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading schema: %v\n", err)
		os.Exit(2)
	}
	baseline, err := loadBaseline(valuesBaselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading values baseline: %v\n", err)
		os.Exit(2)
	}
	var fresh, fixed []string
	checked := 0
	for _, f := range fields {
		for _, value := range f.values {
			checked++
			key := f.key() + "=" + value
			switch ok := facts.handled(f, value); {
			case !ok && !baseline[key]:
				fresh = append(fresh, key)
			case ok && baseline[key]:
				fixed = append(fixed, key)
			}
		}
	}
	sort.Strings(fresh)
	sort.Strings(fixed)
	for _, k := range fixed {
		fmt.Printf("  note - %s is now handled; delete it from %s\n", k, valuesBaselinePath)
	}
	if len(fresh) == 0 {
		fmt.Printf("ok - every documented setting value outside the baseline is handled (%d checked)\n", checked)
		return false
	}
	fmt.Fprintf(os.Stderr, "\ndocumented setting values nothing handles:\n")
	for _, k := range fresh {
		fmt.Fprintf(os.Stderr, "  %s\n", k)
	}
	fmt.Fprintf(os.Stderr, `
The schema offers this choice and no code that reads the field compares
against it, so choosing it does what the default does. Handle it, remove it,
or add it to %s with a note saying why.
`, valuesBaselinePath)
	return true
}
