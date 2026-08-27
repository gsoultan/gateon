// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command checkconfig asserts that every field of every *Config message in the
// protobuf schema is actually read somewhere in non-generated Go.
//
// Three times in three days a configuration field turned out to exist in the
// proto, be rendered as a control in the dashboard, be documented as a feature,
// and be read by no line of code:
//
//   - geoip.xdp_geofencing drove EbpfManager.BlockCountry, which wrote to a map
//     no BPF program read. A dashboard switch labelled "kernel-level geofencing"
//     was wired to nothing.
//   - ha.auth_pass is the field whose entire purpose is authenticating VRRP
//     adverts. Nothing read it, so anyone who could reach the port could make
//     the master release its virtual IP.
//   - ha.enable_gossip and three neighbours. Gossip keyed off HaConfig.Enabled,
//     the port was hardcoded, and Join was never called.
//
// Two of the three were security controls that reported success while enforcing
// nothing. Review did not catch any of them, because nothing about a field being
// unread is visible at a call site — the evidence is an absence, and absences do
// not show up in diffs.
//
// Usage:
//
//	go run ./scripts/checkconfig
//
// Fields listed in baseline.txt are known, accepted debt: the check fails only
// on newly-dead config, the same way `make lint-new` gates new work while the
// pre-existing backlog is paid down opportunistically.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	protoDir     = "proto/gateon/v1"
	baselinePath = "scripts/checkconfig/baseline.txt"
)

// Only *Config messages are checked. Request/response types are wire contracts
// whose fields are legitimately read by generated code alone; configuration is
// where the "renders in the UI, read by nobody" failure lives.
var (
	commentRE = regexp.MustCompile(`//[^\n]*`)
	messageRE = regexp.MustCompile(`(?s)message\s+(\w*Config)\s*\{(.*?)\n\}`)
	// A field is "<type> <name> = <number>;". Enum values have only one token
	// before the "=", so they do not match. map<k,v> is spelled out explicitly
	// because the angle brackets defeat the plain identifier pattern.
	fieldRE = regexp.MustCompile(`(?m)^\s*(?:repeated\s+|optional\s+)?(?:map<[^>]+>|[\w.]+)\s+(\w+)\s*=\s*\d+\s*;`)
)

// goName renders a proto field name the way protoc-gen-go does: split on
// underscores and capitalise each part, with no initialism special-casing
// (database_url becomes DatabaseUrl, not DatabaseURL).
func goName(field string) string {
	parts := strings.Split(field, "_")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

type protoField struct{ Message, Field, Accessor string }

func (f protoField) key() string { return f.Message + "." + f.Field }

// collectFields parses the schema. It is deliberately a regex parser rather than
// a protobuf reflection walk: reflection would only see fields that survived
// code generation, and the whole question is what the generated code is missing.
func collectFields() ([]protoField, error) {
	entries, err := os.ReadDir(protoDir)
	if err != nil {
		return nil, err
	}
	var out []protoField
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(protoDir, e.Name()))
		if err != nil {
			return nil, err
		}
		body := commentRE.ReplaceAllString(string(raw), "")
		for _, m := range messageRE.FindAllStringSubmatch(body, -1) {
			for _, f := range fieldRE.FindAllStringSubmatch(m[2], -1) {
				out = append(out, protoField{Message: m[1], Field: f[1], Accessor: goName(f[1])})
			}
		}
	}
	return out, nil
}

// protoPkgPath is the generated package whose types the config lives on.
const protoPkgPath = "github.com/gsoultan/gateon/proto/gateon/v1"

// readSelections returns, per proto message type, the set of names selected on a
// value of that type — both direct field access (cfg.Redis.Password) and the
// generated getter (cfg.GetRedis().GetPassword()).
//
// This is type-resolved rather than grepped, because a textual search matches an
// accessor name anywhere it appears on any type. "Enabled" occurs on nearly every
// config message and is read somewhere for a hundred others, so a grep can never
// flag a dead Enabled; "Password" is read for auth while RedisConfig.password is
// dropped on the floor. A check that reports "ok" for config nothing reads is the
// very failure it exists to catch, one level up.
func readSelections() (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	// Build constraints hide readers: internal/ebpf/manager_linux.go is
	// //go:build linux, so loading only the host platform on a Mac reports every
	// field it reads as dead. Each GOOS is loaded and the results unioned, so a
	// field read on any supported platform counts as read.
	for _, goos := range []string{"linux", "darwin"} {
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
			// Tests excluded: a field exercised only by a test is still wired to
			// no behaviour, which is the condition being detected.
			Tests: false,
			Env:   append(os.Environ(), "GOOS="+goos),
		}
		pkgs, err := packages.Load(cfg, "./...")
		if err != nil {
			return nil, fmt.Errorf("loading for GOOS=%s: %w", goos, err)
		}
		for _, pkg := range pkgs {
			// The generated code obviously mentions every field; only
			// hand-written callers count as somebody reading the config.
			if pkg.PkgPath == protoPkgPath || pkg.TypesInfo == nil {
				continue
			}
			for _, file := range pkg.Syntax {
				recordSelections(file, pkg.TypesInfo, out)
			}
		}
	}
	return out, nil
}

// recordSelections walks one file, noting every selection made on a proto type.
func recordSelections(file *ast.File, info *types.Info, out map[string]map[string]bool) {
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		tv, ok := info.Types[sel.X]
		if !ok || tv.Type == nil {
			return true
		}
		name := protoTypeName(tv.Type)
		if name == "" {
			return true
		}
		if out[name] == nil {
			out[name] = map[string]bool{}
		}
		out[name][sel.Sel.Name] = true
		return true
	})
}

// protoTypeName returns the bare type name when t is (a pointer to) a named type
// declared in the generated proto package, and "" otherwise.
func protoTypeName(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	if named.Obj().Pkg().Path() != protoPkgPath {
		return ""
	}
	return named.Obj().Name()
}

// loadBaseline reads the accepted-debt list.
func loadBaseline() (map[string]bool, error) {
	out := map[string]bool{}
	raw, err := os.ReadFile(baselinePath)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out[line] = true
		}
	}
	return out, nil
}

func main() {
	fields, err := collectFields()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading schema: %v\n", err)
		os.Exit(2)
	}
	selections, err := readSelections()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: loading packages: %v\n", err)
		os.Exit(2)
	}
	baseline, err := loadBaseline()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading baseline: %v\n", err)
		os.Exit(2)
	}

	var unread, fixed []string
	for _, f := range fields {
		// Read only if selected on its own message type, by field or by getter.
		onType := selections[f.Message]
		referenced := onType[f.Accessor] || onType["Get"+f.Accessor]
		switch {
		case !referenced && !baseline[f.key()]:
			unread = append(unread, fmt.Sprintf("%s (no Go reads %s)", f.key(), f.Accessor))
		case referenced && baseline[f.key()]:
			fixed = append(fixed, f.key())
		}
	}
	sort.Strings(unread)
	sort.Strings(fixed)

	for _, k := range fixed {
		fmt.Printf("  note - %s is now read; delete it from %s\n", k, baselinePath)
	}
	if len(unread) == 0 {
		fmt.Printf("ok - every config field outside the baseline is read by Go (%d checked)\n", len(fields))
		return
	}
	fmt.Fprintf(os.Stderr, "\nconfig fields that nothing reads:\n")
	for _, u := range unread {
		fmt.Fprintf(os.Stderr, "  %s\n", u)
	}
	fmt.Fprintf(os.Stderr, `
A field that exists in the proto and is rendered by the dashboard but is read by
no Go code is a control wired to nothing. Either read it, remove it (reserving
the tag), or add it to %s with a note saying why.
`, baselinePath)
	os.Exit(1)
}
