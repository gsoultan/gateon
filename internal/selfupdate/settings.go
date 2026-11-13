// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The environment variables of the release check.
const (
	// EnvCheck turns the check off when it is a false value ("0", "false").
	// It wins over the setting, for a host that must never call out.
	EnvCheck = "GATEON_UPDATE_CHECK"
	// EnvSource is the release source when the setting names none.
	EnvSource = "GATEON_UPDATE_SOURCE"
	// EnvInterval overrides the tier's check interval: a Go duration, held
	// between MinInterval and MaxInterval.
	EnvInterval = "GATEON_UPDATE_CHECK_INTERVAL"
)

// The range a check interval is held to. Under an hour is a poll of someone
// else's server; over thirty days is not a check anyone can rely on.
const (
	MinInterval = time.Hour
	MaxInterval = 30 * 24 * time.Hour
)

// Env is the release check's environment, read once when the gateway starts:
// the environment does not change under a running process, and reading it per
// status request would log a mistyped value at the rate the dashboard asks.
type Env struct {
	// CheckOff: EnvCheck switched checking off.
	CheckOff bool
	// Source is EnvSource, or empty.
	Source string
	// Interval is the tier's check interval, or EnvInterval's.
	Interval time.Duration
}

// ReadEnv reads the release check's environment variables.
func ReadEnv() Env {
	return Env{
		CheckOff: envOff(EnvCheck),
		Source:   strings.TrimSpace(os.Getenv(EnvSource)),
		Interval: interval(),
	}
}

// Settings is an UpdateConfig with the environment applied.
type Settings struct {
	// Enabled: the gateway checks on its own, every Interval.
	Enabled bool
	// DisabledByEnv: EnvCheck switched checking off, whatever the setting says.
	DisabledByEnv bool
	// Source is the release source in force. One from the environment was
	// never checked by a save, so a check validates it again.
	Source   string
	Interval time.Duration
}

// Settings resolves the release-check settings in force under c: the saved
// source, then the environment's, then DefaultSource.
func (e Env) Settings(c *gateonv1.UpdateConfig) Settings {
	s := Settings{
		Source:        strings.TrimSpace(c.GetSourceUrl()),
		Interval:      e.Interval,
		DisabledByEnv: e.CheckOff,
		Enabled:       !e.CheckOff && !c.GetCheckDisabled(),
	}
	if s.Source == "" {
		s.Source = e.Source
	}
	if s.Source == "" {
		s.Source = DefaultSource
	}
	return s
}

// envOff reports whether the variable name holds a false value. Unset, empty
// and unparseable are all "not off": a typo must not silently stop the check.
func envOff(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return false
	}
	on, err := strconv.ParseBool(v)
	if err != nil {
		logger.L.LogWarn("ignoring an unparseable value; the release check stays as configured",
			"env", name, "value", v)
		return false
	}
	return !on
}

func interval() time.Duration {
	def := config.CurrentTierDefaults().UpdateCheckInterval
	v := strings.TrimSpace(os.Getenv(EnvInterval))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logger.L.LogWarn("ignoring an unparseable release check interval; using the profile default",
			"env", EnvInterval, "value", v, "default", def.String())
		return def
	}
	return min(max(d, MinInterval), MaxInterval)
}
