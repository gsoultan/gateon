// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// These decide whether a route runs with the limit an operator configured
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

func TestParseFloatStrict(t *testing.T) {
	if got, err := ParseFloatStrict("", 1.5); got != 1.5 || err != nil {
		t.Errorf("ParseFloatStrict(\"\", 1.5) = (%v, %v), want (1.5, nil)", got, err)
	}
	if got, err := ParseFloatStrict(" 0.25 ", 1.5); got != 0.25 || err != nil {
		t.Errorf("ParseFloatStrict(\" 0.25 \", 1.5) = (%v, %v), want (0.25, nil); "+
			"surrounding space is not a malformed value", got, err)
	}

	got, err := ParseFloatStrict("half", 1.5)
	if err == nil {
		t.Error("ParseFloatStrict(\"half\", 1.5) returned no error; a caller that " +
			"wanted to refuse a bad config would accept it")
	}
	if got != 1.5 {
		t.Errorf("ParseFloatStrict(\"half\", 1.5) = %v alongside its error, want the "+
			"default so a caller ignoring err still gets a usable value", got)
	}
}

func TestParseDurationStrict(t *testing.T) {
	if got, err := ParseDurationStrict("", 3*time.Second); got != 3*time.Second || err != nil {
		t.Errorf("ParseDurationStrict(\"\", 3s) = (%v, %v), want (3s, nil)", got, err)
	}
	if got, err := ParseDurationStrict("750ms", 3*time.Second); got != 750*time.Millisecond || err != nil {
		t.Errorf("ParseDurationStrict(\"750ms\", 3s) = (%v, %v), want (750ms, nil)", got, err)
	}

	// The shape an operator actually types: a bare number, which reads as a
	// duration to a human and not to time.ParseDuration.
	got, err := ParseDurationStrict("5", 3*time.Second)
	if err == nil {
		t.Error("ParseDurationStrict(\"5\", 3s) returned no error; a unitless " +
			"number is the most likely way this field is mistyped")
	}
	if got != 3*time.Second {
		t.Errorf("ParseDurationStrict(\"5\", 3s) = %v alongside its error, want the "+
			"default so a caller ignoring err still gets a usable value", got)
	}
}

func TestCfgErrorNamesTheKeyAndValue(t *testing.T) {
	_, err := ParseIntStrict("ten", 0)
	if err == nil {
		t.Fatal("ParseIntStrict(\"ten\", 0) returned no error")
	}
	wrapped := CfgError("max_depth", "ten", err)

	// An operator with twenty settings needs to know which one, and what they
	// wrote, or the message costs them a search.
	msg := wrapped.Error()
	for _, want := range []string{"max_depth", "ten"} {
		if !strings.Contains(msg, want) {
			t.Errorf("CfgError message %q does not contain %q", msg, want)
		}
	}
	if !errors.Is(wrapped, err) {
		t.Error("CfgError does not wrap the cause; errors.Is cannot reach it")
	}
}

func TestParseBoolStrict(t *testing.T) {
	cases := []struct {
		in      string
		def     bool
		want    bool
		wantErr bool
	}{
		{"", true, true, false},
		{"", false, false, false},
		{"true", false, true, false},
		{"false", true, false, false},
		{"1", false, true, false},
		{"0", true, false, false},
		{"TRUE", false, true, false},
		// Unlike the int parsers, this one trims. The asymmetry is the point of
		// testing it: the same stray space that defaults an int is tolerated here.
		{"  true  ", false, true, false},
		// Present and not a boolean is an error, not the default. This read
		// "yes" as false and "on" as true -- whatever the default happened to
		// be -- while the dashboard showed what was typed.
		{"yes", false, false, true},
		{"on", true, true, true},
	}

	for _, tc := range cases {
		got, err := ParseBoolStrict(tc.in, tc.def)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("ParseBoolStrict(%q, %v) = %v, %v; want %v, error %v", tc.in, tc.def, got, err, tc.want, tc.wantErr)
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
