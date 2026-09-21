// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// Middleware configuration arrives as map[string]string from the dashboard and
// from config files, so every subpackage that builds a middleware has to turn
// those strings into numbers and flags the same way. These lived in
// package middleware, which cannot be imported from a subpackage without a
// cycle -- the factory imports the subpackages, not the other way round -- so
// they belong here with the rest of the shared primitives. ADR-0002 calls this
// out as Stage 0's purpose; the traffic stage is simply the first one to need
// them.

func ParsePositiveInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}
func ParseIntStrict(s string, defaultVal int) (int, error) {
	if s == "" {
		return defaultVal, nil
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		return defaultVal, err
	}
	return int(n), nil
}
func ParseBoolStrict(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return defaultVal
	}
	return parsed
}

// The severity and action vocabulary every middleware reports threats in.
//
// Shared here rather than copied per subpackage on purpose. The 2026-09-19
// review found that gwaf grades rules notice/warning/error/critical while the
// correlation engine, SIEM and dashboard speak critical/high/medium/low, so
// every WAF block below critical ranked lowest and the responder never
// escalated. Two spellings of one vocabulary is how that happens; a second
// copy in a subpackage would be the same bet with a shorter fuse.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// The ActionTaken vocabulary is internal/telemetry's, because that package
// owns SecurityThreat and this one already imports it -- the reverse would be
// a cycle. Re-exported here so a middleware writing a threat record does not
// need two imports for one record, and aliased rather than copied so the
// strings cannot drift apart. A second copy is what made the severity values
// diverge for months.
const (
	ActionBlocked    = telemetry.ActionBlocked
	ActionDetected   = telemetry.ActionDetected
	ActionChallenged = telemetry.ActionChallenged
	ActionShunned    = telemetry.ActionShunned
	ActionFlagged    = telemetry.ActionFlagged
	ActionThrottled  = telemetry.ActionThrottled
)

func ParseListStrict(val string) []string {
	if val == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Header names that more than one middleware group needs.
//
// Both arrived the same way: defined in a file that a refactor stage moved,
// while a file that stayed behind was still calling them -- headerAuthorization
// in the traffic stage, headerAccept in the transform stage. Copying the string
// into each package is how two spellings of one header start, so they live here
// with the rest of the shared vocabulary.
const (
	HeaderAccept        = "Accept"
	HeaderAuthorization = "Authorization"
)
