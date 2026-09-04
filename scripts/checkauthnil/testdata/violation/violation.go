// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package violation is a fixture for checkauthnil's own test. It reproduces the
// shapes the checker must catch and the ones it must not, so the gate is watched
// failing rather than assumed to work.
//
// It is under testdata/, which the Go tool excludes from ./... builds, so
// nothing here reaches the binary or the checker's own run over the tree.
package violation

import "github.com/gsoultan/gateon/internal/auth"

type holderField struct {
	AuthManager auth.Service
}

// ViaParameter is the shape the grep in check-security-invariants missed: the
// service arrives as a parameter, so there is no ".AuthManager" to match.
func ViaParameter(verifier auth.Service) bool {
	return verifier == nil
}

// ViaField is the shape the grep did match, kept so the type-aware check is not
// a step backwards.
func ViaField(d *holderField) bool {
	return d.AuthManager != nil
}

// ViaLocal covers a value that never had a name a grep could anticipate.
func ViaLocal(s auth.Service) bool {
	local := s
	return local == nil
}

// NilOnTheLeft is written the other way round.
func NilOnTheLeft(s auth.Service) bool {
	return nil == s
}

// Allowed is what the rule asks for and must never be reported.
func Allowed(s auth.Service) bool {
	return auth.Available(s)
}

// UnrelatedNilCheck compares something that is not an auth.Service, and must not
// be reported: the checker keys off the type, and over-reporting would push
// people to silence it.
func UnrelatedNilCheck(m map[string]string) bool {
	return m == nil
}
