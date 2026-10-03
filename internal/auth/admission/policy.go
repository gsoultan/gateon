// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package admission

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

const (
	// AttemptsPerMinuteEnv overrides the per-client budget on the public
	// sign-in endpoints, in requests a minute (and at once).
	AttemptsPerMinuteEnv = "GATEON_AUTH_ATTEMPTS_PER_MINUTE"
	// HashConcurrencyEnv overrides how many password hashes run at once,
	// besides the reserve.
	HashConcurrencyEnv = "GATEON_AUTH_HASH_CONCURRENCY"
)

// AttemptsPerMinute is the per-client budget: AttemptsPerMinuteEnv when it is
// a positive integer, else the resource profile's AuthAttemptsPerMinute.
func AttemptsPerMinute() int {
	if n, ok := positiveEnv(AttemptsPerMinuteEnv); ok {
		return n
	}
	return config.CurrentTierDefaults().AuthAttemptsPerMinute
}

// HashConcurrency is the gate's general slots: HashConcurrencyEnv when it is a
// positive integer, else the resource profile's AuthHashConcurrency, but never
// more than half the cores the process may use (at least one). Each slot is a
// core while it is busy, and the other half is the data plane's.
func HashConcurrency() int {
	if n, ok := positiveEnv(HashConcurrencyEnv); ok {
		return n
	}
	return min(config.CurrentTierDefaults().AuthHashConcurrency, max(1, runtime.GOMAXPROCS(0)/2))
}

// positiveEnv reads name as a positive integer. Anything else set there is
// ignored, with a warning: these bounds cannot be switched off, and a typo
// must not do it either.
func positiveEnv(name string) (int, bool) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		logger.L.LogWarn("ignoring an invalid sign-in bound; using the profile default", "env", name, "value", v)
		return 0, false
	}
	return n, true
}
