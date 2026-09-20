// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strconv"
	"strings"
)

func parseBool(s string, defaultVal bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return defaultVal
	}
	return s == "true" || s == "1" || s == "yes"
}

func parseBoolStrict(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return defaultVal
	}
	return parsed
}
