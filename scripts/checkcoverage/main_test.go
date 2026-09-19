// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseStdin runs parse over the given text by handing it a real *os.File,
// which is what parse takes. Written into t.TempDir(), never the checkout.
func parseStdin(t *testing.T, text string) []result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cover.txt")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) //nolint:gosec // path is t.TempDir()-derived
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got, err := parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return got
}

func find(got []result, pkg string) (result, bool) {
	for _, r := range got {
		if r.pkg == pkg {
			return r, true
		}
	}
	return result{}, false
}

// A package whose tests fail, or that does not compile, emits no coverage line
// of its own. Before this was recognised it was simply absent from the parsed
// run, so every check in main skipped it and the gate printed "ok" for a
// package it had not looked at.
//
// That is not academic: `make check-coverage` is
//
//	go test -cover $(go list ./...) | tee /dev/stderr | go run ./scripts/checkcoverage
//
// and a shell pipeline exits with the status of its *last* stage, so this
// command's exit code is the one make sees. A red test run therefore came out
// of the local gate as a green one.
func TestFailedPackageIsRecognisedRatherThanSkipped(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"tests failed", "FAIL\tgithub.com/x/a\t0.4s"},
		{"build failed", "FAIL\tgithub.com/x/a [build failed]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStdin(t, "ok  \tgithub.com/x/b\t0.5s\tcoverage: 50.0% of statements\n"+tc.line+"\n")

			r, ok := find(got, "github.com/x/a")
			if !ok {
				t.Fatalf("github.com/x/a is absent from the parsed run (%+v); "+
					"every check in main iterates over what parse returned, so an "+
					"absent package is one the gate silently reports ok for", got)
			}
			if !r.failed {
				t.Errorf("github.com/x/a parsed as %+v, want failed=true", r)
			}
		})
	}
}

// The bare "FAIL" summary line carries no package name. Treating it as one
// would invent a package called "FAIL" and fail every run that has any failure
// twice, with the second message naming nothing.
func TestBareFailLineIsNotAPackage(t *testing.T) {
	got := parseStdin(t, "--- FAIL: TestZ (0.00s)\nFAIL\ncoverage: 12.0% of statements\nFAIL\tgithub.com/x/a\t0.4s\n")

	for _, r := range got {
		if r.pkg == "FAIL" || r.pkg == "" {
			t.Errorf("parsed a package named %q from a bare FAIL line: %+v", r.pkg, r)
		}
	}
	if r, ok := find(got, "github.com/x/a"); !ok || !r.failed {
		t.Errorf("the package-carrying FAIL line was not recorded: %+v", got)
	}
}

// A green run must still parse exactly as before: an ok line is coverage, a "?"
// line and an indented 0.0% line are both "no tests". Recognising failures must
// not reclassify anything that already worked.
func TestGreenRunParsesUnchanged(t *testing.T) {
	got := parseStdin(t, strings.Join([]string{
		"ok  \tgithub.com/x/a\t0.5s\tcoverage: 80.0% of statements",
		"?   \tgithub.com/x/b\t[no test files]",
		"\tgithub.com/x/c\t\tcoverage: 0.0% of statements",
		"",
	}, "\n"))

	if len(got) != 3 {
		t.Fatalf("parsed %d packages, want 3: %+v", len(got), got)
	}
	for _, tc := range []struct {
		pkg      string
		hasTests bool
		cov      float64
	}{
		{"github.com/x/a", true, 80.0},
		{"github.com/x/b", false, 0},
		{"github.com/x/c", false, 0},
	} {
		r, ok := find(got, tc.pkg)
		if !ok {
			t.Errorf("%s missing from the parse", tc.pkg)
			continue
		}
		if r.failed {
			t.Errorf("%s parsed as failed in a green run", tc.pkg)
		}
		if r.hasTests != tc.hasTests || r.coverage != tc.cov {
			t.Errorf("%s = %+v, want hasTests=%v coverage=%.1f", tc.pkg, r, tc.hasTests, tc.cov)
		}
	}
}
