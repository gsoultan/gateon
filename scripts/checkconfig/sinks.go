// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
)

// A config value read into a struct field nothing reads is as dead as a field
// nobody reads at all -- and the first check cannot see it, because the read
// that fills the struct counts as a read. That is how the XFCC "Forward By"
// switch passed it for months (T38): cfg["forward_by"] was read, stored in
// XFCCConfig.ForwardBy, and nothing ever looked at ForwardBy again. The
// dashboard showed the switch; the header never carried By=.
//
// So a second question is asked of every struct field in this module that is
// written from configuration: is it read anywhere? "From configuration" means
// the written value contains a middleware config lookup (cfg["key"] on a
// map[string]string, or BoolFields.Get("key", ...)) or a read of a proto
// *Config message. "Read" means selected anywhere other than as the target of
// that write.
//
// Limits, stated so nobody mistakes this for more than it is: it follows the
// value one hop, into the field it is stored in, not through locals or
// function arguments; a field read only through reflection (encoding/json)
// counts as unread and belongs in the baseline with a note -- except a
// json-tagged field of a management API response type, which encoding/json
// reads; and it cannot tell
// a field that is read but whose behaviour is wrong (an inverted threshold, a
// switch that removes rules the engine never loads) -- that takes a test that
// flips the setting and watches the effect, which is the effect registry's
// job (effects.go).

// sinkWrite is the first config-fed write seen for a field.
type sinkWrite struct {
	name string // pkg.Type.Field
	at   string // file:line of the write
}

// sinkFacts accumulates, over every loaded package and platform, the
// config-fed writes and the reads of struct fields, keyed by the field's
// declaration position (stable across the per-GOOS loads).
type sinkFacts struct {
	writes map[string]sinkWrite
	reads  map[string]bool
}

func newSinkFacts() *sinkFacts {
	return &sinkFacts{writes: map[string]sinkWrite{}, reads: map[string]bool{}}
}

// sinkScan is one file's walk.
type sinkScan struct {
	fset    *token.FileSet
	info    *types.Info
	facts   *sinkFacts
	written map[*ast.Ident]bool // field idents in write position
}

// recordSinks walks one file: first the writes, then every other selection.
func recordSinks(fset *token.FileSet, file *ast.File, info *types.Info, facts *sinkFacts) {
	s := &sinkScan{fset: fset, info: info, facts: facts, written: map[*ast.Ident]bool{}}
	ast.Inspect(file, s.visitWrite)
	ast.Inspect(file, s.visitRead)
}

func (s *sinkScan) visitWrite(n ast.Node) bool {
	switch x := n.(type) {
	case *ast.CompositeLit:
		s.compositeWrites(x)
	case *ast.AssignStmt:
		s.assignWrites(x)
	}
	return true
}

// compositeWrites: T{Field: value}.
func (s *sinkScan) compositeWrites(lit *ast.CompositeLit) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		field := s.moduleField(s.info.Uses[key])
		if field == nil {
			continue
		}
		s.written[key] = true
		if s.configFed(kv.Value) && !wireField(s.info.TypeOf(lit), field) {
			s.recordWrite(field, typeName(s.info.TypeOf(lit)), kv.Pos())
		}
	}
}

// assignWrites: x.Field = value.
func (s *sinkScan) assignWrites(as *ast.AssignStmt) {
	for i, lhs := range as.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		selection, ok := s.info.Selections[sel]
		if !ok || selection.Kind() != types.FieldVal {
			continue
		}
		field := s.moduleField(selection.Obj())
		if field == nil {
			continue
		}
		s.written[sel.Sel] = true
		rhs := as.Rhs[0]
		if len(as.Rhs) == len(as.Lhs) {
			rhs = as.Rhs[i]
		}
		if s.configFed(rhs) && !wireField(selection.Recv(), field) {
			s.recordWrite(field, typeName(selection.Recv()), sel.Pos())
		}
	}
}

func (s *sinkScan) visitRead(n ast.Node) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || s.written[sel.Sel] {
		return true
	}
	if selection, ok := s.info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
		if field := s.moduleField(selection.Obj()); field != nil {
			s.facts.reads[s.fset.Position(field.Pos()).String()] = true
		}
	}
	return true
}

func (s *sinkScan) recordWrite(field *types.Var, owner string, at token.Pos) {
	key := s.fset.Position(field.Pos()).String()
	if _, seen := s.facts.writes[key]; seen {
		return
	}
	pos := s.fset.Position(at)
	s.facts.writes[key] = sinkWrite{
		name: owner + "." + field.Name(),
		at:   fmt.Sprintf("%s:%d", relPath(pos.Filename), pos.Line),
	}
}

// moduleField returns obj when it is a struct field declared in this module,
// outside the generated proto package.
func (s *sinkScan) moduleField(obj types.Object) *types.Var {
	v, ok := obj.(*types.Var)
	if !ok || !v.IsField() || v.Pkg() == nil {
		return nil
	}
	path := v.Pkg().Path()
	if !strings.HasPrefix(path, modulePath+"/") || path == protoPkgPath {
		return nil
	}
	return v
}

// configFed reports whether e reads configuration: a string-keyed lookup in a
// map[string]string (a middleware's config), BoolFields.Get("key", ...), or a
// field or getter of a proto *Config message.
func (s *sinkScan) configFed(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.IndexExpr:
			found = isStringLit(x.Index) && isStringMap(s.info.TypeOf(x.X))
		case *ast.CallExpr:
			found = s.isBoolFieldsGet(x)
		case *ast.SelectorExpr:
			found = strings.HasSuffix(protoTypeName(s.info.TypeOf(x.X)), "Config")
		}
		return !found
	})
	return found
}

func (s *sinkScan) isBoolFieldsGet(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" || len(call.Args) == 0 || !isStringLit(call.Args[0]) {
		return false
	}
	return strings.HasSuffix(typeName(s.info.TypeOf(sel.X)), ".BoolFields")
}

// transportPackages hold the management API's response types. A field of
// one with a json tag is read by encoding/json when the response is written,
// which no selector shows.
var transportPackages = []string{modulePath + "/internal/server/handlers", modulePath + "/internal/api"}

// wireField reports whether field is a json-tagged field of a response type.
func wireField(owner types.Type, field *types.Var) bool {
	if !slices.Contains(transportPackages, field.Pkg().Path()) || owner == nil {
		return false
	}
	if ptr, ok := owner.(*types.Pointer); ok {
		owner = ptr.Elem()
	}
	st, ok := owner.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if st.Field(i) == field {
			return reflect.StructTag(st.Tag(i)).Get("json") != ""
		}
	}
	return false
}

func isStringLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

func isStringMap(t types.Type) bool {
	if t == nil {
		return false
	}
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return false
	}
	k, kok := m.Key().Underlying().(*types.Basic)
	v, vok := m.Elem().Underlying().(*types.Basic)
	return kok && vok && k.Kind() == types.String && v.Kind() == types.String
}

// typeName renders (a pointer to) a named type as pkg.Name.
func typeName(t types.Type) string {
	if t == nil {
		return "?"
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok && named.Obj() != nil {
		if pkg := named.Obj().Pkg(); pkg != nil {
			return pkg.Name() + "." + named.Obj().Name()
		}
		return named.Obj().Name()
	}
	return t.String()
}

// deadSinks lists the config-fed fields nothing reads, by name, with where
// each was written from configuration.
func (f *sinkFacts) deadSinks() map[string]string {
	out := map[string]string{}
	for key, w := range f.writes {
		if !f.reads[key] {
			out[w.name] = w.at
		}
	}
	return out
}

// relPath trims the working directory so reports and the baseline read the
// same on every machine.
func relPath(p string) string {
	if i := strings.Index(p, "/internal/"); i >= 0 {
		return p[i+1:]
	}
	if i := strings.Index(p, "/pkg/"); i >= 0 {
		return p[i+1:]
	}
	if i := strings.Index(p, "/cmd/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
