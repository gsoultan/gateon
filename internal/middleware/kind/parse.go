// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"strconv"
	"strings"
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

	ActionBlocked  = "blocked"
	ActionDetected = "detected"
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
