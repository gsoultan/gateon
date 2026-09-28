// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Every automatic shun -- the address shun of ADR 0029, the anomaly
// detector's, a playbook's, the incident responder's -- held until an
// operator released it, and a release exempted the address from all of them
// for good, while a fingerprint block lasts an hour and its release holds a
// day. A shun refuses everyone behind the address, on every route. ADR 0031.

// onEachShunEngine runs a test on SQLite and, when GATEON_TEST_POSTGRES_DSN is
// set, on Postgres: the expiry is compared in SQL, written once for both.
func onEachShunEngine(t *testing.T, test func(t *testing.T)) {
	t.Run("sqlite", func(t *testing.T) {
		openShunStore(t, "sqlite://"+filepath.Join(t.TempDir(), "shun.db"))
		test(t)
	})
	t.Run("postgres", func(t *testing.T) {
		openShunStore(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
		test(t)
	})
}

// openShunStore opens the store on databaseURL with no address shun in it.
func openShunStore(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	if _, err := getStore().db.Exec(`DELETE FROM ip_mitigations`); err != nil {
		t.Fatalf("empty ip_mitigations: %v", err)
	}
	// A shared Postgres keeps rows across tests, and an operator's block never
	// lapses: leave the table as it was found. Runs before the close above.
	t.Cleanup(func() {
		if s := getStore(); s != nil {
			_, _ = s.db.Exec(`DELETE FROM ip_mitigations`)
		}
	})
	purgeShunCache()
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
}

// purgeShunCache drops what the enforcement cache remembers, so the next
// answer is the database's.
func purgeShunCache() {
	if s := getStore(); s != nil && s.unmitigatedCache != nil {
		s.unmitigatedCache.Purge()
	}
}

// attackFromClasses records one WAF block from each of n client classes at ip:
// what earns the address shun (ADR 0029).
func attackFromClasses(ip, tag string, n int) {
	for i := range n {
		escalateMitigation(&SecurityThreat{
			Type: "waf_block", Category: "waf", SourceIP: ip, Mitigated: true,
			Fingerprint: fmt.Sprintf("t13d%02d%s_8daaf6152771_b0da82dd1658", i, tag), Time: time.Now(),
		})
	}
}

// ageIPShun moves ip's shun d into the past, as if it had been written d ago:
// when it was written, and when it ends if it does, each shifted by d, so a
// shun written with no real end is still in force afterwards.
func ageIPShun(t *testing.T, ip string, d time.Duration) {
	t.Helper()
	s := getStore()
	const layout = "2006-01-02 15:04:05"
	past := time.Now().UTC().Add(-d).Format(layout)
	if _, err := s.db.Exec(s.dialect.Rebind(`UPDATE ip_mitigations SET mitigated_at = ? WHERE ip = ?`), past, ip); err != nil {
		t.Fatalf("age the shun: %v", err)
	}
	var end sql.NullTime
	// No such column before the expiry existed: then there is no end to move.
	if s.db.QueryRow(s.dialect.Rebind(`SELECT expires_at FROM ip_mitigations WHERE ip = ?`), ip).Scan(&end) == nil && end.Valid {
		moved := end.Time.UTC().Add(-d).Format(layout)
		if _, err := s.db.Exec(s.dialect.Rebind(`UPDATE ip_mitigations SET expires_at = ? WHERE ip = ?`), moved, ip); err != nil {
			t.Fatalf("age the shun's end: %v", err)
		}
	}
	purgeShunCache()
}

// An automatic shun lifts when it lapses, with nothing sweeping the row: the
// request path's own check reads the end, and the list stops showing it.
func TestAnAutomaticShunLapses(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.140"
		attackFromClasses(ip, "lapse", ipShunMinClasses)
		if !IsIPMitigated(ip) {
			t.Fatalf("%d attacking classes did not shun %s; the rest proves nothing", ipShunMinClasses, ip)
		}

		ageIPShun(t, ip, 16*time.Minute)
		if IsIPMitigated(ip) {
			t.Errorf("an automatic shun written 16 minutes ago still refuses %s: it never lapses, so an "+
				"office shunned by mistake stays offline until an operator finds the row", ip)
		}
		if _, total := GetIPMitigations(t.Context(), 50, 0); total != 0 {
			t.Errorf("the mitigation list still counts %d shun(s) after it lapsed", total)
		}
	})
}

// A release holds the automatic paths off an address for a day, as a
// fingerprint release does, and no longer: past the hold, fresh evidence
// shuns it again.
func TestAReleaseHoldsForADayNotForever(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.141"
		attackFromClasses(ip, "first", ipShunMinClasses)
		if err := MarkIPUnmitigated(ip); err != nil {
			t.Fatal(err)
		}
		attackFromClasses(ip, "held", ipShunMinClasses)
		if IsIPMitigated(ip) {
			t.Fatal("an address released a moment ago was shunned again: the release did not hold")
		}

		s := getStore()
		dayAgo := time.Now().UTC().Add(-25 * time.Hour).Format("2006-01-02 15:04:05")
		if _, err := s.db.Exec(s.dialect.Rebind(`UPDATE ip_mitigations SET unmitigated_at = ? WHERE ip = ?`), dayAgo, ip); err != nil {
			t.Fatal(err)
		}
		purgeShunCache()
		resetAddressEvidence()
		attackFromClasses(ip, "later", ipShunMinClasses)
		if !IsIPMitigated(ip) {
			t.Errorf("%s was released 25 hours ago and is attacking again from %d client builds, and "+
				"is not shunned: a release exempted it from every automatic shun for good", ip, ipShunMinClasses)
		}
	})
}
