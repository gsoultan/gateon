// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// This gate ran in CI with no tests of its own, which is a particular kind of
// risk for this one: everything it reports is an *absence*, so when it stops
// seeing something it goes quiet rather than wrong. A field its parser misses
// is a field it says nothing about, and "nothing" is what it prints when all
// is well.

func TestGoNameMatchesProtocGenGo(t *testing.T) {
	cases := map[string]string{
		"enabled":           "Enabled",
		"auth_pass":         "AuthPass",
		"xdp_geofencing":    "XdpGeofencing",
		"l4_proxy_protocol": "L4ProxyProtocol",
		// protoc-gen-go does no initialism special-casing, and neither may
		// this: if it rendered DatabaseURL the accessor would not match the
		// generated field, the field would look unread, and the gate would
		// fail on config that is perfectly alive.
		"database_url": "DatabaseUrl",
		"ca_file":      "CaFile",
	}
	for in, want := range cases {
		if got := goName(in); got != want {
			t.Errorf("goName(%q) = %q, want %q", in, got, want)
		}
	}
}

// writeProto drops a schema fixture into its own directory.
func writeProto(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.proto"), []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func fieldKeys(t *testing.T, dir string) []string {
	t.Helper()
	fields, err := collectFields(dir)
	if err != nil {
		t.Fatalf("collectFields: %v", err)
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.key())
	}
	sort.Strings(out)
	return out
}

// TestCollectFieldsSeesEveryFieldForm is the important one. Each form below is
// a way a field can be written; one the parser does not match is a field that
// can be dead forever while this gate prints "ok".
func TestCollectFieldsSeesEveryFieldForm(t *testing.T) {
	dir := writeProto(t, `
syntax = "proto3";
message HaConfig {
  bool enabled = 1;
  repeated string peers = 2;
  optional string auth_pass = 3;
  map<string, string> labels = 4;
  // A field carrying options does not end in "= <number>;". Before this was
  // handled the parser skipped it silently.
  bool legacy_mode = 5 [deprecated = true];
  NestedType nested = 6;
  enum Mode {
    ACTIVE = 0;
    PASSIVE = 1;
  }
}
`)
	got := fieldKeys(t, dir)
	want := []string{
		"HaConfig.auth_pass", "HaConfig.enabled", "HaConfig.labels",
		"HaConfig.legacy_mode", "HaConfig.nested", "HaConfig.peers",
	}
	if len(got) != len(want) {
		t.Fatalf("collected %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collected %v, want %v", got, want)
		}
	}
}

// Enum values are "NAME = 0;" -- one token before the "=" -- so they must not
// be mistaken for fields. A phantom field is a permanent false failure, which
// gets the gate disabled.
func TestCollectFieldsIgnoresEnumValuesAndNonConfigMessages(t *testing.T) {
	dir := writeProto(t, `
syntax = "proto3";
enum TopLevel {
  FIRST = 0;
  SECOND = 1;
}
message GetUserRequest {
  string id = 1;
}
message RedisConfig {
  string password = 1;
}
`)
	got := fieldKeys(t, dir)
	if len(got) != 1 || got[0] != "RedisConfig.password" {
		t.Errorf("collected %v, want only RedisConfig.password; request types are "+
			"wire contracts read by generated code, and enum values are not fields", got)
	}
}

// A commented-out field is not a field. Counting one produces a failure an
// operator cannot fix, because there is nothing to read.
func TestCollectFieldsIgnoresCommentedOutFields(t *testing.T) {
	dir := writeProto(t, `
syntax = "proto3";
message WafConfig {
  bool enabled = 1;
  // string removed_setting = 2;
}
`)
	got := fieldKeys(t, dir)
	if len(got) != 1 || got[0] != "WafConfig.enabled" {
		t.Errorf("collected %v, want only WafConfig.enabled", got)
	}
}

func TestLoadBaselineSkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.txt")
	body := "# a comment\n\nHaConfig.auth_pass\n  WafConfig.enabled  \n\n# another\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	got, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("loadBaseline: %v", err)
	}
	if len(got) != 2 || !got["HaConfig.auth_pass"] || !got["WafConfig.enabled"] {
		t.Errorf("loadBaseline = %v, want the two entries with comments and blanks dropped", got)
	}
}

// A missing baseline means "nothing is excused", not "fail". The gate has to
// work on a checkout that has never had one.
func TestLoadBaselineTreatsAbsentFileAsEmpty(t *testing.T) {
	got, err := loadBaseline(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err != nil {
		t.Fatalf("loadBaseline on a missing file returned %v; a checkout without "+
			"a baseline must still be checkable", err)
	}
	if len(got) != 0 {
		t.Errorf("loadBaseline = %v, want empty", got)
	}
}
