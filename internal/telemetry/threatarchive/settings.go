// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package threatarchive keeps the security threats retention deletes. Each
// prune step's expired threats go to one gzip-compressed NDJSON file under the
// data directory before their rows are deleted, so the archive grows on disk,
// not in the database, and reading it back never queries the database.
package threatarchive

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
// profile's default, the same order the trace archive uses.
const (
	EnvEnabled = "GATEON_THREAT_ARCHIVE_ENABLED"
	EnvMaxMB   = "GATEON_THREAT_ARCHIVE_MAX_MB"
	EnvDir     = "GATEON_THREAT_ARCHIVE_DIR"
)

// Settings is the archive's effective configuration.
type Settings struct {
	// Enabled turns archiving on. Off by default on every tier.
	Enabled bool
	// MaxBytes is the most disk the archive may use; past it the oldest files
	// go first.
	MaxBytes int64
	// Dir is the directory the archive files live in.
	Dir string
}

// CurrentSettings resolves the settings as they stand now. It is cheap enough
// to call on every use, so a config change takes effect without a restart.
func CurrentSettings() Settings {
	s := Settings{
		MaxBytes: config.CurrentTierDefaults().ThreatArchiveMaxBytes,
		Dir:      filepath.Join(config.DataDir(), "security", "archives"),
	}
	s.applyConfig(config.GetGlobalConfig().GetLog())
	s.applyEnv()
	return s
}

func (s *Settings) applyConfig(l *gateonv1.LogConfig) {
	s.Enabled = l.GetSecurityThreatArchiveEnabled()
	if mb := l.GetSecurityThreatArchiveMaxSizeMb(); mb > 0 {
		s.MaxBytes = int64(mb) << 20
	}
}

// applyEnv takes each variable that is set and valid. A malformed one is
// ignored rather than guessed at, so a typo does not overrule the config.
func (s *Settings) applyEnv() {
	if b, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnvEnabled))); err == nil {
		s.Enabled = b
	}
	if mb, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(EnvMaxMB)), 10, 64); err == nil && mb > 0 {
		s.MaxBytes = min(mb, 1<<40) << 20
	}
	if dir := strings.TrimSpace(os.Getenv(EnvDir)); dir != "" {
		s.Dir = dir
	}
}
