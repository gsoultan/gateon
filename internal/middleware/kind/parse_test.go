// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import "testing"

// These four decide whether a route runs with the limit an operator configured
// or with a default, and every one of them falls back silently. A typo in a
// config value does not produce an error anywhere -- it produces a gateway
// running on a number nobody chose. So the contract each of them actually has,
// including the parts that are surprising, is pinned here rather than inferred
// from the call sites.

func TestParsePositiveInt(t *testing.T) {
	cases := []struct {
		name string
		in   string
		def  int
		want int
	}{
		{"unset falls back", "", 42, 42},
		{"a plain number is taken", "7", 42, 7},
		// Despite the name, zero is accepted: the guard is n < 0, not n <= 0.
		// Callers that treat 0 as "disabled" depend on that, so it is behaviour
		// rather than an oversight -- but the name does not say so.
		{"zero is accepted, not rejected", "0", 42, 0},
		{"negative falls back", "-1", 42, 42},
		{"non-numeric falls back", "lots", 42, 42},
		// No TrimSpace here, unlike ParseBoolStrict. A config value that picked
		// up a trailing space silently reverts to the default.
		{"surrounding space falls back", " 7 ", 42, 42},
		{"a float falls back", "7.5", 42, 42},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParsePositiveInt(tc.in, tc.def); got != tc.want {
				t.Errorf("ParsePositiveInt(%q, %d) = %d, want %d", tc.in, tc.def, got, tc.want)
			}
		})
	}
}

// TestParseIntStrict covers the one parser that reports its failure. The
// distinction matters: a caller that wants to refuse a bad config rather than
// quietly default has to use this one, and it still returns the default
// alongside the error, so a caller ignoring err gets the fallback rather than
// a zero.
func TestParseIntStrict(t *testing.T) {
	if got, err := ParseIntStrict("", 9); got != 9 || err != nil {
		t.Errorf("ParseIntStrict(\"\", 9) = (%d, %v), want (9, nil)", got, err)
	}
	if got, err := ParseIntStrict("13", 9); got != 13 || err != nil {
		t.Errorf("ParseIntStrict(\"13\", 9) = (%d, %v), want (13, nil)", got, err)
	}
	if got, err := ParseIntStrict("-4", 9); got != -4 || err != nil {
		t.Errorf("ParseIntStrict(\"-4\", 9) = (%d, %v), want (-4, nil); "+
			"this parser does not constrain sign", got, err)
	}

	got, err := ParseIntStrict("nope", 9)
	if err == nil {
		t.Error("ParseIntStrict(\"nope\", 9) returned no error; a caller that " +
			"wanted to refuse a bad config would accept it")
	}
	if got != 9 {
		t.Errorf("ParseIntStrict(\"nope\", 9) = %d alongside its error, want the "+
			"default 9 so a caller ignoring err still gets a usable value", got)
	}
}

func TestParseBoolStrict(t *testing.T) {
	cases := []struct {
		in   string
		def  bool
		want bool
	}{
		{"", true, true},
		{"", false, false},
		{"true", false, true},
		{"false", true, false},
		{"1", false, true},
		{"0", true, false},
		{"TRUE", false, true},
		// Unlike the int parsers, this one trims. The asymmetry is the point of
		// testing it: the same stray space that defaults an int is tolerated here.
		{"  true  ", false, true},
		{"yes", false, false},
		{"on", true, true},
	}

	for _, tc := range cases {
		if got := ParseBoolStrict(tc.in, tc.def); got != tc.want {
			t.Errorf("ParseBoolStrict(%q, %v) = %v, want %v", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestParseListStrict(t *testing.T) {
	if got := ParseListStrict(""); got != nil {
		t.Errorf("ParseListStrict(\"\") = %#v, want nil", got)
	}
	// A list of nothing but separators is nil, not a slice of empty strings --
	// which matters because an empty entry in an allowlist is an entry that
	// matches "".
	if got := ParseListStrict(" , ,, "); got != nil {
		t.Errorf("ParseListStrict(\" , ,, \") = %#v, want nil; an empty entry in "+
			"an allowlist is an entry that matches the empty string", got)
	}

	got := ParseListStrict(" a, b ,,c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("ParseListStrict = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseListStrict[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSeverityAndActionVocabularyIsLowerCase guards the constants themselves.
// Every consumer of a threat record lower-cases before comparing, so a
// constant defined in upper case here would make every middleware that uses it
// invisible to the correlation engine, the SIEM mapping and the dashboard --
// which is exactly the bug these constants were introduced to end.
func TestSeverityAndActionVocabularyIsLowerCase(t *testing.T) {
	for name, val := range map[string]string{
		"SeverityCritical": SeverityCritical,
		"SeverityHigh":     SeverityHigh,
		"SeverityMedium":   SeverityMedium,
		"SeverityLow":      SeverityLow,
		"ActionBlocked":    ActionBlocked,
		"ActionDetected":   ActionDetected,
	} {
		if val == "" {
			t.Errorf("%s is empty", name)
		}
		for _, r := range val {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("%s = %q contains an upper-case letter; consumers "+
					"compare lower-case, so this value would rank below \"low\" "+
					"and the dashboard would never count it", name, val)
				break
			}
		}
	}
}
