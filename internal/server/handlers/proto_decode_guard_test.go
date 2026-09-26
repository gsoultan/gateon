// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Decoding a protobuf message with encoding/json is silently wrong, and this
// package did it eleven times.
//
// encoding/json matches an incoming key against the generated struct tag —
// `json:"anomaly_type"` — while every client of this API sends protojson's
// lowerCamel spelling, "anomalyType". Those do not match, and not for a reason
// the decoder can recover from: its fallback is case-insensitive, and an
// underscore is not a capital T. The field is dropped. No error, no 400.
//
// What that cost, in this package alone:
//
//   - ApplyRecommendation lost anomaly_type, so "Apply automatic fix" answered
//     "Automatic resolution for '' is not implemented yet" for every anomaly
//     type there is, and had never once worked.
//   - The same drop lost threat_id, silently disabling the fingerprint
//     mitigation that ApplyRecommendation performs alongside the fix.
//   - PUT /v1/users lost two_factor_pending, so editing a user's role quietly
//     cleared an admin-mandated 2FA enrollment and reported success.
//
// Every one of those looked like a feature that did nothing rather than a bug,
// which is why they survived. A field that arrives empty is indistinguishable
// from a field the caller omitted.
//
// DecodeProtoRequest uses protojson, which accepts both spellings. This test
// exists because the next person to add a handler will reach for
// json.NewDecoder out of habit, the failure will be silent again, and no
// reviewer reliably catches an absence.
//
// Anonymous structs are fine and are the reason this checks the declared type
// rather than banning encoding/json outright: a handler that declares its own
// shape owns its own tags -- but only their spelling is its to choose, not
// their convention. TestHandlerJSONTagsUseTheDashboardsSpelling holds those
// tags to the dashboard's lowerCamel.

var (
	// var req gateonv1.SomeRequest
	protoVarDecl = regexp.MustCompile(`var\s+(\w+)\s+gateonv1\.\w+`)
	// json.NewDecoder(...).Decode(&req) or json.Unmarshal(..., &req)
	jsonDecodeInto = regexp.MustCompile(`json\.(?:NewDecoder\([^)]*\)\.Decode|Unmarshal\([^,]*,)\s*\(?&(\w+)`)
)

func TestNoProtoMessageDecodedWithEncodingJSON(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	type offence struct {
		file string
		line int
		name string
	}
	var found []offence

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- test-time read of this package's own sources
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		lines := strings.Split(string(src), "\n")

		// Track the most recent proto-typed declaration per identifier. A
		// handler body is short and declares its request immediately before
		// decoding it, so a small look-back window is enough and keeps this
		// from matching an unrelated variable of the same name elsewhere.
		const lookBack = 8
		for i, line := range lines {
			m := jsonDecodeInto.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			target := m[1]
			for j := i; j >= 0 && j > i-lookBack; j-- {
				d := protoVarDecl.FindStringSubmatch(lines[j])
				if d != nil && d[1] == target {
					found = append(found, offence{file: f, line: i + 1, name: target})
					break
				}
			}
		}
	}

	for _, o := range found {
		t.Errorf("%s:%d decodes the protobuf message %q with encoding/json.\n"+
			"    Use DecodeProtoRequest, which decodes with protojson.\n"+
			"    encoding/json matches the generated `json:\"snake_case\"` tag, but every\n"+
			"    client sends protojson's lowerCamel spelling, so any field whose proto\n"+
			"    name contains an underscore is dropped without an error.",
			o.file, o.line, o.name)
	}
}

// The guard is only worth having if it can actually see an offence, and a
// regex that silently matches nothing would pass this package forever.
func TestProtoDecodeGuardDetectsTheShapeItLooksFor(t *testing.T) {
	sample := []string{
		`	var req gateonv1.ApplyRecommendationRequest`,
		`	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {`,
	}

	d := protoVarDecl.FindStringSubmatch(sample[0])
	if d == nil || d[1] != "req" {
		t.Fatalf("declaration pattern did not match a known-bad declaration: %v", d)
	}
	m := jsonDecodeInto.FindStringSubmatch(sample[1])
	if m == nil || m[1] != "req" {
		t.Fatalf("decode pattern did not match a known-bad decode: %v", m)
	}

	// And it must not flag a handler that declares its own struct, which is the
	// legitimate use of encoding/json still present in this package.
	if protoVarDecl.MatchString(`	var req struct {`) {
		t.Error("declaration pattern matches an anonymous struct; those own their own tags")
	}
}

// The dashboard, which calls every handler in this package, writes and reads
// protojson's lowerCamel, so a handler-declared tag with an underscore never
// matches it -- in either direction. Four shipped that way and all four passed
// the check above, because each was a struct of the handler's own:
// POST /v1/setup/test-db answered "missing database configuration" to every
// test the setup wizard ran, POST /v1/setup saved none of the databases it
// chose, POST /v1/geoip/update ignored the licence key the settings card sent,
// and GET /v1/system/interfaces reported the eBPF attach mode under a key the
// card never read.
var snakeCaseJSONTag = regexp.MustCompile(`json:"([a-z0-9]+_[a-z0-9_]*)[",]`)

// snakeCaseTagsAllowed names, as "file:key", the keys that are not the
// dashboard's to spell.
var snakeCaseTagsAllowed = map[string]bool{
	// The export file's own format: GET /v1/config/export writes it, and import
	// and validate read it back. The dashboard uploads the file it downloaded
	// without reading it, and renaming the key would break every export on disk.
	"config_import_export.go:entry_points": true,
}

func TestHandlerJSONTagsUseTheDashboardsSpelling(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- test-time read of this package's own sources
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // a comment may quote a tag; only a declaration carries one
			}
			for _, m := range snakeCaseJSONTag.FindAllStringSubmatch(line, -1) {
				if snakeCaseTagsAllowed[f+":"+m[1]] {
					continue
				}
				t.Errorf("%s:%d declares the JSON key %q.\n"+
					"    The dashboard sends and reads protojson's lowerCamel, which never matches it.\n"+
					"    Decode a proto message with DecodeProtoRequest, or spell the tag in lowerCamel.",
					f, i+1, m[1])
			}
		}
	}
}

// The tag check has to see the shapes that shipped, and let the right ones by.
func TestSnakeCaseTagGuardDetectsTheShapeItLooksFor(t *testing.T) {
	for _, shipped := range []string{
		"LicenseKey string `json:\"maxmind_license_key\"`",
		"DatabaseConfig *gateonv1.DatabaseConfig `json:\"database_config\"`",
		"AttachMode string `json:\"attach_mode,omitempty\"`",
	} {
		if !snakeCaseJSONTag.MatchString(shipped) {
			t.Errorf("did not flag %s", shipped)
		}
	}
	for _, fine := range []string{
		"AttachMode string `json:\"attachMode,omitempty\"`",
		"Success bool `json:\"success,omitzero\"`",
		"Path string `json:\"path\"`",
	} {
		if snakeCaseJSONTag.MatchString(fine) {
			t.Errorf("flagged %s", fine)
		}
	}
}
