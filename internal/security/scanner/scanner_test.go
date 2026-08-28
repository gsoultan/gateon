// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanner

import (
	"reflect"
	"testing"
)

func TestScanFindsPatterns(t *testing.T) {
	t.Parallel()

	s := NewScanner([]string{"<script", "javascript:", "union select"})

	for _, tc := range []struct {
		input string
		want  bool
	}{
		{"<script>alert(1)</script>", true},
		{"click javascript:void(0)", true},
		{"1 union select password from users", true},
		{"perfectly ordinary text", false},
		{"", false},
	} {
		if got := s.Scan(tc.input); got != tc.want {
			t.Errorf("Scan(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// TestScanIsCaseInsensitive pins AsciiCaseInsensitive, which is the option that
// makes this useful against evasion: an attacker writing <ScRiPt> must not walk
// past a detector configured in lower case.
func TestScanIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	s := NewScanner([]string{"<script", "union select"})

	for _, input := range []string{
		"<SCRIPT>", "<ScRiPt>", "1 UNION SELECT x", "1 Union Select x",
	} {
		if !s.Scan(input) {
			t.Errorf("Scan(%q) = false; the matcher is meant to be case-insensitive", input)
		}
	}
}

// TestEmptyPatternListMatchesNothing guards the degenerate construction. A
// matcher built from no patterns that answered true would turn an unconfigured
// detector into one that flags every request.
func TestEmptyPatternListMatchesNothing(t *testing.T) {
	t.Parallel()

	s := NewScanner(nil)
	if s.Scan("anything at all") {
		t.Error("a scanner with no patterns matched")
	}
	if got := s.FindAll("anything at all"); got != nil {
		t.Errorf("FindAll on a patternless scanner = %v, want nil", got)
	}

	s2 := NewScanner([]string{})
	if s2.Scan("anything at all") {
		t.Error("a scanner built from an empty slice matched")
	}
}

// TestEmptyPatternDoesNotMatchEverything is the sharper version of the same
// hazard: one empty string among real patterns matches at every position, so a
// single bad entry would make the detector fire on all traffic. The patterns are
// compile-time constants today; this fails loudly if they ever become
// operator-supplied without validation.
func TestEmptyPatternDoesNotMatchEverything(t *testing.T) {
	t.Parallel()

	s := NewScanner([]string{"<script", ""})
	if s.Scan("perfectly ordinary text") {
		t.Error("an empty pattern made the scanner match text containing none " +
			"of its real patterns")
	}
}

func TestFindAllReturnsTheMatchedText(t *testing.T) {
	t.Parallel()

	s := NewScanner([]string{"<script", "onerror"})

	got := s.FindAll("<script src=x onerror=alert(1)")
	want := []string{"<script", "onerror"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FindAll = %v, want %v", got, want)
	}

	if got := s.FindAll("nothing here"); got != nil {
		t.Errorf("FindAll with no matches = %v, want nil", got)
	}
}

// TestFindAllSlicesOnRuneBoundaries checks that a match found after multi-byte
// text is sliced by the same byte offsets the matcher reports. Getting this
// wrong produces mojibake in a security log, which is where the operator is
// least able to tell corruption from an attack.
func TestFindAllSlicesOnRuneBoundaries(t *testing.T) {
	t.Parallel()

	s := NewScanner([]string{"<script"})

	const input = "日本語のテキスト <script> more"
	got := s.FindAll(input)
	if len(got) != 1 {
		t.Fatalf("FindAll = %v, want exactly one match", got)
	}
	if got[0] != "<script" {
		t.Errorf("FindAll = %q, want %q; the byte offsets were sliced wrong",
			got[0], "<script")
	}
}

// TestScanDoesNotRegress pins Scan's allocation cost rather than wishing it
// away. The library's Iter allocates and offers no single-match alternative, so
// three per call is the floor available today; the value of the test is that it
// fails if someone makes it worse on a request-path function.
func TestScanDoesNotRegress(t *testing.T) {
	// No t.Parallel: AllocsPerRun must not run alongside other tests.
	s := NewScanner([]string{"<script", "union select"})

	const budget = 3
	if n := testing.AllocsPerRun(100, func() {
		_ = s.Scan("a fairly ordinary query string value")
	}); n > budget {
		t.Errorf("Scan allocates %v times per run, budget is %d", n, budget)
	}
}
