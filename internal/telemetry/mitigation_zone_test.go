// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

// TestFingerprintMitigationTTLIgnoresTheDatabaseZone.
//
// A fingerprint block counts while updated_at is newer than mitigationCutoff(),
// a UTC wall clock computed in Go. updated_at is written by CURRENT_TIMESTAMP,
// which SQLite renders in UTC -- and which Postgres renders in the session's
// TimeZone when it lands in a TIMESTAMP (without time zone) column. The session
// zone is whatever the server was installed with unless the client says
// otherwise, and gateon never said. So on a Postgres set to a zone behind UTC
// every block was older than its own cutoff the moment it was written and
// never stopped a request, and on one ahead of UTC a one-hour block lasted
// hours longer.
//
// The server's default zone is emulated here with the session parameter a DSN
// can carry, which sets the same thing a postgresql.conf timezone does.
func TestFingerprintMitigationTTLIgnoresTheDatabaseZone(t *testing.T) {
	dsn := testutil.PostgresDSN(t, "only Postgres renders CURRENT_TIMESTAMP in a session zone")
	// POSIX sign convention: Etc/GMT+5 is five hours behind UTC.
	for _, zone := range []string{"Etc/GMT+5", "Etc/GMT-9"} {
		t.Run(zone, func(t *testing.T) {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatalf("parse DSN: %v", err)
			}
			q := u.Query()
			q.Set("timezone", zone)
			u.RawQuery = q.Encode()
			assertMitigationTTLHolds(t, u.String())
		})
	}
}

func assertMitigationTTLHolds(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	s := getStore()
	fp := fmt.Sprintf("t13d1516h2_zone_%d", time.Now().UnixNano())
	defer func() {
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM user_mitigations WHERE fingerprint = ?"), fp)
	}()

	MarkUserMitigated(fp, "JA4+", "zone test", "waf")
	if !IsUserMitigated(fp) {
		t.Fatalf("a block written a moment ago is not in force")
	}

	// Age the row past its TTL in the database's own arithmetic, so what is
	// asserted is the comparison, not how the row's clock was produced.
	age := s.dialect.Rebind("UPDATE user_mitigations SET updated_at = updated_at - (? * INTERVAL '1 second') WHERE fingerprint = ?")
	if _, err := s.db.Exec(age, int((mitigationTTL + time.Minute).Seconds()), fp); err != nil {
		t.Fatalf("age the row: %v", err)
	}
	if IsUserMitigated(fp) {
		t.Errorf("a block older than its %v TTL is still in force", mitigationTTL)
	}
}
