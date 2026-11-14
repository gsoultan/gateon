// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The file-integrity monitor's two settings arrive as strings an operator
// typed into an environment variable. A blank entry between separators must
// not become a path to watch, and an interval that does not parse must fall
// back to the default rather than to "never".
func TestFIMPathListDropsBlankEntries(t *testing.T) {
	sep := string(os.PathListSeparator)
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"unset", "", nil},
		{"only spaces", "   ", nil},
		{"one path", "/etc/gateon", []string{"/etc/gateon"}},
		{"two paths, padded", " /etc/gateon " + sep + " /usr/bin/gateon", []string{"/etc/gateon", "/usr/bin/gateon"}},
		{"blank entries", strings.Join([]string{"/etc/gateon", "", "  ", "/usr/bin/gateon", ""}, sep), []string{"/etc/gateon", "/usr/bin/gateon"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parsePathList(c.raw); !slices.Equal(got, c.want) {
				t.Fatalf("parsePathList(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestFIMIntervalFallsBackToTheDefaultWhenItDoesNotParse(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", 0},
		{"90s", 90 * time.Second},
		{"5m", 5 * time.Minute},
		{"five minutes", 0},
		{"300", 0},
	}
	for _, c := range cases {
		if got := parseDuration(c.raw); got != c.want {
			t.Errorf("parseDuration(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}
