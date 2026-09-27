// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The environment variables that override the archive's configuration. An
// environment variable beats the global config, which beats the resource
// profile's default -- the order GATEON_PROFILE and GATEON_TRACE_SAMPLE_RATE
// already use, so a container can pin the archive whatever the stored config
// says.
const (
	EnvEnabled       = "GATEON_TRACE_ARCHIVE_ENABLED"
	EnvDir           = "GATEON_TRACE_ARCHIVE_DIR"
	EnvRetentionDays = "GATEON_TRACE_ARCHIVE_RETENTION_DAYS"
	EnvMaxMB         = "GATEON_TRACE_ARCHIVE_MAX_MB"
)

// Settings is the archive's effective configuration.
type Settings struct {
	// Enabled turns archiving on. Off by default on every tier.
	Enabled bool
	// RetentionDays is how long an archived hour is kept.
	RetentionDays int
	// MaxBytes is the most disk the archive may use; past it the oldest hours
	// go first, whatever their age.
	MaxBytes int64
	// Dir is the archive's root directory.
	Dir string
}

// CurrentSettings resolves the settings as they stand now. It is cheap enough
// to call on every use, which is how a change to the global config takes effect
// without a restart.
func CurrentSettings() Settings {
	td := config.CurrentTierDefaults()
	s := Settings{
		RetentionDays: td.TraceArchiveRetentionDays,
		MaxBytes:      td.TraceArchiveMaxBytes,
		Dir:           filepath.Join(config.DataDir(), "trace_archive"),
	}
	s.applyConfig(config.GetGlobalConfig().GetLog())
	s.applyEnv()
	return s
}

func (s *Settings) applyConfig(l *gateonv1.LogConfig) {
	s.Enabled = l.GetTraceArchiveEnabled()
	if d := l.GetTraceArchiveRetentionDays(); d > 0 {
		s.RetentionDays = int(d)
	}
	if mb := l.GetTraceArchiveMaxSizeMb(); mb > 0 {
		s.MaxBytes = int64(mb) << 20
	}
}

// applyEnv takes each variable that is set and valid. One that is set but
// malformed is ignored rather than guessed at: the value underneath it is a
// configuration someone chose, and a typo should not overrule it.
func (s *Settings) applyEnv() {
	if b, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnvEnabled))); err == nil {
		s.Enabled = b
	}
	if d, ok := positiveEnv(EnvRetentionDays); ok {
		s.RetentionDays = int(min(d, 1<<20))
	}
	if mb, ok := positiveEnv(EnvMaxMB); ok {
		s.MaxBytes = min(mb, 1<<40) << 20
	}
	if dir := strings.TrimSpace(os.Getenv(EnvDir)); dir != "" {
		s.Dir = dir
	}
}

func positiveEnv(name string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64)
	return n, err == nil && n > 0
}
