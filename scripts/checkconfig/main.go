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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

// skipDir keeps the scan to hand-written Go.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", "vendor", "ui", "graphify-out", ".serena":
		return true
	}
	return false
}

// readGoSources concatenates every non-generated, non-test Go file.
//
// Tests are excluded on purpose: a field exercised only by a test is still not
// wired to any behaviour, which is exactly the condition being detected.
func readGoSources() (string, error) {
	var sb strings.Builder
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable paths are not the check's business
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, ".pb.go") ||
			strings.HasSuffix(name, "_test.go") ||
			strings.Contains(path, "/gen/") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr == nil {
			sb.Write(b)
			sb.WriteByte('\n')
		}
		return nil
	})
	return sb.String(), err
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
	sources, err := readGoSources()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading sources: %v\n", err)
		os.Exit(2)
	}
	baseline, err := loadBaseline()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkconfig: reading baseline: %v\n", err)
		os.Exit(2)
	}

	var unread, fixed []string
	for _, f := range fields {
		// Matches both direct field access and the generated getter.
		re := regexp.MustCompile(`\b(?:Get)?` + regexp.QuoteMeta(f.Accessor) + `\b`)
		referenced := re.MatchString(sources)
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
