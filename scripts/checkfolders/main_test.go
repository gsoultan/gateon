// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckRatchet is the negative test the invariant rules require: every way
// the ratchet is meant to fail, shown failing. A gate nobody has watched fail is
// indistinguishable from a gate that cannot.
func TestCheckRatchet(t *testing.T) {
	tests := []struct {
		name     string
		counts   map[string]int
		baseline map[string]int
		wantPkg  string
		wantSays string
	}{
		{
			name:     "under the limit and unlisted is fine",
			counts:   map[string]int{"internal/ha": 4},
			baseline: map[string]int{},
		},
		{
			name:     "exactly at the limit is fine",
			counts:   map[string]int{"internal/ha": limit},
			baseline: map[string]int{},
		},
		{
			name:     "pinned package holding its baseline is fine",
			counts:   map[string]int{"internal/middleware": 67},
			baseline: map[string]int{"internal/middleware": 67},
		},
		{
			name:     "a tenth package crossing the limit fails",
			counts:   map[string]int{"internal/ha": limit + 1},
			baseline: map[string]int{},
			wantPkg:  "internal/ha",
			wantSays: "over the limit",
		},
		{
			name:     "a pinned package growing fails",
			counts:   map[string]int{"internal/api": 37},
			baseline: map[string]int{"internal/api": 36},
			wantPkg:  "internal/api",
			wantSays: "grew from 36 to 37",
		},
		{
			name:     "a pinned package shrinking without banking the gain fails",
			counts:   map[string]int{"internal/api": 30},
			baseline: map[string]int{"internal/api": 36},
			wantPkg:  "internal/api",
			wantSays: "Lower its line",
		},
		{
			name:     "a baseline line for a package that no longer exists fails",
			counts:   map[string]int{},
			baseline: map[string]int{"internal/gone": 12},
			wantPkg:  "internal/gone",
			wantSays: "no longer exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.counts, tt.baseline)
			if tt.wantPkg == "" {
				if len(got) != 0 {
					t.Fatalf("want no violations, got %d: %+v", len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want exactly one violation, got %d: %+v", len(got), got)
			}
			if got[0].pkg != tt.wantPkg {
				t.Errorf("violation package = %q, want %q", got[0].pkg, tt.wantPkg)
			}
			if !strings.Contains(got[0].detail, tt.wantSays) {
				t.Errorf("violation detail = %q, want it to mention %q", got[0].detail, tt.wantSays)
			}
		})
	}
}

// TestCountableExcludesTestsAndGeneratedCode pins the two exclusions the count
// depends on. Counting _test.go would penalise writing tests, and counting
// bpf2go output would make a C change look like a Go design regression.
func TestCountableExcludesTestsAndGeneratedCode(t *testing.T) {
	tests := map[string]bool{
		"factory.go":           true,
		"waf.go":               true,
		"factory_test.go":      false,
		"gateon_ebpf_bpf.go":   false,
		"gateon_ebpf_bpfel.go": false,
		"README.md":            false,
		"doc.go":               true,
		"attach_linux.go":      true,
		"attach_linux_test.go": false,
	}
	for name, want := range tests {
		if got := countable(name); got != want {
			t.Errorf("countable(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestReadBaselineRejectsMalformedLines makes a typo in the baseline a loud
// parse error rather than a silently dropped pin, which would quietly let a
// package grow unbounded.
func TestReadBaselineRejectsMalformedLines(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("# a comment\n\n67 internal/middleware\n11 internal/middleware/auth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readBaseline(good)
	if err != nil {
		t.Fatalf("readBaseline on a valid file: %v", err)
	}
	if parsed["internal/middleware"] != 67 || parsed["internal/middleware/auth"] != 11 {
		t.Errorf("parsed = %+v, want the two pins", parsed)
	}

	for _, bad := range []string{"internal/middleware\n", "sixty-seven internal/middleware\n"} {
		path := filepath.Join(dir, "bad.txt")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBaseline(path); err == nil {
			t.Errorf("readBaseline(%q) = nil error, want a parse failure", bad)
		}
	}
}

// TestCountPackagesWalksTheRealTree drives countPackages over a temporary tree
// rather than testing skipDir and countable in isolation. A test on the helpers
// alone keeps passing if the walk stops calling them, which is the exact way a
// gate goes quiet without going red.
func TestCountPackagesWalksTheRealTree(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		"internal/ha/election.go",
		"internal/ha/election_test.go", // tests do not count
		"internal/ha/testdata/fake.go", // fixtures do not count
		"internal/ebpf/attach.go",
		"internal/ebpf/gateon_ebpf_bpf.go", // generated, does not count
		"pkg/proxy/proxy.go",
		"proto/gateon/v1/config.pb.go", // outside roots entirely
		"internal/.hidden/tool.go",     // dot-directory
		"docs/notes.md",                // not Go
	}
	for _, f := range files {
		path := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package p\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)

	got, err := countPackages()
	if err != nil {
		t.Fatalf("countPackages: %v", err)
	}
	want := map[string]int{
		"internal/ha":   1,
		"internal/ebpf": 1,
		"pkg/proxy":     1,
	}
	if len(got) != len(want) {
		t.Fatalf("counted %d packages (%+v), want %d (%+v)", len(got), got, len(want), want)
	}
	for pkg, n := range want {
		if got[pkg] != n {
			t.Errorf("count[%q] = %d, want %d", pkg, got[pkg], n)
		}
	}
}

// TestSkipDirSkipsGeneratedProtobuf pins the one entry in skipDirs. Its path is
// matched with forward slashes, so this would fail on Windows if the walk ever
// stopped normalising.
func TestSkipDirSkipsGeneratedProtobuf(t *testing.T) {
	if !skipDir(filepath.FromSlash("proto/gateon/v1"), "v1") {
		t.Error("skipDir(proto/gateon/v1) = false, want the generated tree skipped")
	}
	if skipDir(filepath.FromSlash("internal/middleware"), "middleware") {
		t.Error("skipDir(internal/middleware) = true, want hand-written code counted")
	}
}
