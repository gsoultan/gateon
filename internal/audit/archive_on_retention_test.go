// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// With audit.archive_on_retention off, log.archive_on_retention still has
// expired entries archived before they are deleted -- read from the saved
// global config on the retention pass, with no restart -- and with both off
// they are deleted without an archive, as before.
func TestCheckRetention_ArchiveOnRetentionArchivesAuditEntries(t *testing.T) {
	t.Setenv(config.EnvArchiveOnRetention, "")
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	save := func(on bool) {
		t.Helper()
		if err := reg.Update(context.Background(), &gateonv1.GlobalConfig{Log: &gateonv1.LogConfig{ArchiveOnRetention: on}}); err != nil {
			t.Fatalf("save the global config: %v", err)
		}
	}
	archives := func(dir string) []string {
		t.Helper()
		got, err := filepath.Glob(filepath.Join(dir, "audit", "archives", "*.json.br"))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	audit := &gateonv1.AuditConfig{Enabled: true, RetentionDays: 30}

	t.Run("on", func(t *testing.T) {
		save(true)
		m := newTestManager(t, audit)
		insertAt(t, m, "old", time.Now().AddDate(0, 0, -90))
		dir := t.TempDir()
		t.Setenv("GATEON_DATA_DIR", dir)

		m.checkRetention()

		if n := countRows(t, m); n != 0 {
			t.Fatalf("got %d rows, want the expired entry retired", n)
		}
		if got := archives(dir); len(got) != 1 {
			t.Fatalf("archives = %v, want one: archive everything was on, so the entry must be archived before it is deleted", got)
		}
	})

	t.Run("off", func(t *testing.T) {
		save(false)
		m := newTestManager(t, audit)
		insertAt(t, m, "old", time.Now().AddDate(0, 0, -90))
		dir := t.TempDir()
		t.Setenv("GATEON_DATA_DIR", dir)

		m.checkRetention()

		if n := countRows(t, m); n != 0 {
			t.Fatalf("got %d rows, want the expired entry deleted", n)
		}
		if got := archives(dir); len(got) != 0 {
			t.Fatalf("archives = %v, want none with both switches off", got)
		}
	})
}
