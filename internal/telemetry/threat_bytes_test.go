// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestThreatCarryingBytesPostgresRefusesIsStillRecorded.
//
// Go's HTTP server hands a handler bytes Postgres will not store: a
// percent-encoded %00 or %FF decodes into r.URL.Path, and a header value may
// carry anything above 0x7F. Postgres refuses a TEXT value that is not valid
// UTF-8 or that contains NUL, and flushThreats isolates each insert in a
// savepoint, so the refused row was simply dropped -- the threat, and with it
// the forensic record, of exactly the request that chose to carry such a byte.
// On Postgres, an attacker could opt out of the Security Hub by appending \xff
// to their User-Agent. SQLite stores anything and never showed it.
func TestThreatCarryingBytesPostgresRefusesIsStillRecorded(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertThreatWithHostileBytesRecorded(t, "sqlite://"+filepath.Join(t.TempDir(), "bytes.db"))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("GATEON_TEST_POSTGRES_DSN not set; skipping the Postgres run")
		}
		assertThreatWithHostileBytesRecorded(t, dsn)
	})
}

func assertThreatWithHostileBytesRecorded(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	s := getStore()
	id := fmt.Sprintf("hostile-bytes-%d", time.Now().UnixNano())
	defer func() {
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM security_threats WHERE id = ?"), id)
	}()

	th := GetSecurityThreat()
	*th = SecurityThreat{
		ID:          id,
		Type:        "waf_block",
		Category:    "waf",
		SourceIP:    "203.0.113.91",
		UserAgent:   "sqlmap/1.8\xff",
		Details:     "union select in path /a\x00b",
		RequestURI:  "/a%00b",
		ActionTaken: ActionBlocked,
		Time:        time.Now(),
	}
	// The flush itself, synchronously, rather than through the writer loop.
	s.flushThreats([]*SecurityThreat{th})

	got, err := GetSecurityThreatByID(context.Background(), id)
	if err != nil {
		t.Fatalf("on %s a threat whose request carried a NUL or a non-UTF-8 byte was not recorded: %v",
			s.dialect.Driver, err)
	}
	if !strings.HasPrefix(got.UserAgent, "sqlmap/1.8") || !strings.Contains(got.Details, "union select") {
		t.Errorf("the recorded threat lost its evidence: user agent %q, details %q", got.UserAgent, got.Details)
	}
}
