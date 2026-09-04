// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"strings"
	"testing"
)

// TestRunFindsEveryShape drives the checker over a fixture holding one of each
// comparison it must catch, and two it must not. The parameter case is the one
// that matters: it is what slipped past the grep this tool replaces, in
// isLogsRequestAuthorized, where it authorized the system log stream.
func TestRunFindsEveryShape(t *testing.T) {
	found, err := run("./testdata/violation")
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	wantExprs := map[string]bool{
		"verifier == nil":      false,
		"d.AuthManager != nil": false,
		"local == nil":         false,
		"nil == s":             false,
	}
	for _, f := range found {
		if _, expected := wantExprs[f.expr]; !expected {
			t.Errorf("reported something it should not have: %s: %s", f.pos, f.expr)
			continue
		}
		wantExprs[f.expr] = true
	}
	for expr, seen := range wantExprs {
		if !seen {
			t.Errorf("missed %q; the checker would not have caught it", expr)
		}
	}
}

// TestRunIsQuietOnCleanCode keeps the checker from being one nobody trusts. It
// runs over its own package, which compares nothing to nil.
func TestRunIsQuietOnCleanCode(t *testing.T) {
	found, err := run(".")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("reported %d finding(s) in clean code: %+v", len(found), found)
	}
}

// TestFindingsNameTheirLocation checks the message is actionable. A gate that
// says only "something is wrong" costs more time than it saves.
func TestFindingsNameTheirLocation(t *testing.T) {
	found, err := run("./testdata/violation")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no findings to inspect")
	}
	for _, f := range found {
		if !strings.Contains(f.pos, "violation.go:") {
			t.Errorf("position %q does not name the file and line", f.pos)
		}
		if f.expr == "" {
			t.Errorf("finding at %s has no expression to look for", f.pos)
		}
	}
}
