// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package passpolicy

import (
	"errors"
	"strings"
	"testing"
)

// TestCheckRefusesWhatTheReviewSetAndWorse pins M11: "a" and "" were accepted.
func TestCheckRefusesWhatTheReviewSetAndWorse(t *testing.T) {
	cases := []struct {
		password, username string
		want               error
	}{
		{"", "admin", ErrEmpty},
		{"a", "admin", ErrTooShort},
		{"elevenchars", "admin", ErrTooShort},
		{strings.Repeat("x", MaxBytes) + "y", "admin", ErrTooLong},
		{"Password1234", "admin", ErrCommon},
		{"123456789012", "admin", ErrCommon},
		{"ADMINISTRATOR", "root", ErrCommon},
		{"alice-is-the-best", "alice", ErrUsername},
		{"aaaaaaaaaaaaaa", "admin", ErrRepeated},
		{"abcdefghijklm", "admin", ErrRepeated},
		{"zyxwvutsrqponm", "admin", ErrRepeated},
	}
	for _, tc := range cases {
		err := Check(tc.password, tc.username)
		if !errors.Is(err, tc.want) {
			t.Errorf("Check(%q, %q) = %v, want %v", tc.password, tc.username, err, tc.want)
		}
		if !errors.Is(err, ErrWeak) {
			t.Errorf("Check(%q) = %v, which does not wrap ErrWeak", tc.password, err)
		}
	}
}

// TestCheckAcceptsAnOrdinaryPassphrase is the control: the policy must not
// refuse what it exists to encourage.
func TestCheckAcceptsAnOrdinaryPassphrase(t *testing.T) {
	for _, p := range []string{
		"correct horse battery",
		"tulip-arrow-quarry-9",
		"Ünïcödé-pässwörd",       // 16 runes, more bytes: length counts characters
		strings.Repeat("ab", 36), // exactly MaxBytes
	} {
		if err := Check(p, "admin"); err != nil {
			t.Errorf("Check(%q) = %v, want nil", p, err)
		}
	}
}

// TestShortUsernameIsNotMatched: a two-letter username would refuse half the
// dictionary, so the username rule starts at three characters.
func TestShortUsernameIsNotMatched(t *testing.T) {
	if err := Check("my-ed-passphrase", "ed"); err != nil {
		t.Errorf("a password containing a two-letter username was refused: %v", err)
	}
}
