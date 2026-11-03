// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// log.archive_on_retention turns this archive on with its own switch off,
// never turns it off when its own switch is on, and the archive's own
// variable still has the last word.
func TestSettings_ArchiveOnRetentionTurnsThisArchiveOn(t *testing.T) {
	t.Setenv(EnvEnabled, "")
	t.Setenv(config.EnvArchiveOnRetention, "")
	cases := []struct {
		name     string
		umbrella string
		own      string
		log      *gateonv1.LogConfig
		want     bool
	}{
		{"both off", "", "", &gateonv1.LogConfig{}, false},
		{"only archive everything", "", "", &gateonv1.LogConfig{ArchiveOnRetention: true}, true},
		{"only its own switch", "", "", &gateonv1.LogConfig{TraceArchiveEnabled: true}, true},
		{"archive everything off by env leaves its own switch on", "false", "", &gateonv1.LogConfig{TraceArchiveEnabled: true, ArchiveOnRetention: true}, true},
		{"archive everything on by env", "true", "", &gateonv1.LogConfig{}, true},
		{"its own env off beats archive everything", "", "false", &gateonv1.LogConfig{ArchiveOnRetention: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(config.EnvArchiveOnRetention, c.umbrella)
			t.Setenv(EnvEnabled, c.own)
			var s Settings
			s.applyConfig(c.log)
			s.applyEnv()
			if s.Enabled != c.want {
				t.Fatalf("Enabled = %v, want %v", s.Enabled, c.want)
			}
		})
	}
}
