// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package passpolicy decides whether a password may be set. See ADR 0050.
//
// There was no rule: "a" was accepted for an administrator, and "" stored an
// empty hash. The rule now follows NIST SP 800-63B's shape -- length, and not a
// password everyone tries first -- rather than composition rules, which push
// people towards "Password1!". It is offline and costs a map lookup: no
// breached-password service is called, so the check works on an air-gapped
// host and sends nobody a hash of anything.
package passpolicy

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// MinLength is the fewest characters a password may have. Twelve, not
	// eight: a management password guards the whole gateway, the sign-in
	// throttle allows a determined attacker a few hundred guesses a day, and
	// many accounts will not have a second factor.
	MinLength = 12
	// MaxBytes is bcrypt's input limit. Go's bcrypt refuses a longer password
	// rather than silently truncating it, so a longer one could never be set.
	MaxBytes = 72
)

// ErrWeak is wrapped by every refusal, so a caller can map all of them to one
// status without listing them.
var ErrWeak = errors.New("password does not meet the password policy")

var (
	ErrEmpty    = fmt.Errorf("%w: a password is required", ErrWeak)
	ErrTooShort = fmt.Errorf("%w: it must be at least %d characters", ErrWeak, MinLength)
	ErrTooLong  = fmt.Errorf("%w: it must be at most %d bytes", ErrWeak, MaxBytes)
	ErrCommon   = fmt.Errorf("%w: it is a commonly used password", ErrWeak)
	ErrUsername = fmt.Errorf("%w: it must not contain the username", ErrWeak)
	ErrRepeated = fmt.Errorf("%w: it must not be one character repeated or a simple sequence", ErrWeak)
)

//go:embed common.txt
var commonList string

// common is the embedded list, lower-cased, one entry per line.
var common = func() map[string]struct{} {
	m := make(map[string]struct{}, 256)
	for line := range strings.SplitSeq(commonList, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = struct{}{}
	}
	return m
}()

// Check refuses a password that may not be set for the account username,
// with an error wrapping ErrWeak that says why.
func Check(password, username string) error {
	switch {
	case password == "":
		return ErrEmpty
	case utf8.RuneCountInString(password) < MinLength:
		return ErrTooShort
	case len(password) > MaxBytes:
		return ErrTooLong
	}
	lower := strings.ToLower(password)
	if _, ok := common[lower]; ok {
		return ErrCommon
	}
	if u := strings.ToLower(strings.TrimSpace(username)); len(u) >= 3 && strings.Contains(lower, u) {
		return ErrUsername
	}
	if trivial(lower) {
		return ErrRepeated
	}
	return nil
}

// trivial reports a password that is one character repeated, or a run in
// which every character is the one before it plus or minus one:
// "aaaaaaaaaaaa", "abcdefghijkl", "zyxwvutsrqpo". Runs that wrap, such as
// "123456789012", are on the list instead.
func trivial(s string) bool {
	runes := []rune(s)
	same, up, down := true, true, true
	for i := 1; i < len(runes); i++ {
		d := runes[i] - runes[i-1]
		same = same && d == 0
		up = up && d == 1
		down = down && d == -1
	}
	return same || up || down
}
