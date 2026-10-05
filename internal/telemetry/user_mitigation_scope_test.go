// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
	"github.com/gsoultan/gateon/internal/testutil"
)

// onEachEngine runs a store test on SQLite and, when GATEON_TEST_POSTGRES_DSN
// is set, on Postgres: the queries behind a scoped block (a prefix match, the
// in-force filter, the prune) are written once for both.
func onEachEngine(t *testing.T, test func(t *testing.T)) {
	t.Run("sqlite", func(t *testing.T) {
		openScopeStore(t, "sqlite://"+filepath.Join(t.TempDir(), "scope.db"))
		test(t)
	})
	t.Run("postgres", func(t *testing.T) {
		openScopeStore(t, testutil.PostgresDSN(t, "skipping the Postgres run"))
		test(t)
	})
}

// openScopeStore opens the store on databaseURL with no fingerprint block in
// it, and closes it with the test. A shared Postgres keeps rows across runs,
// so the table is emptied first.
func openScopeStore(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	s := getStore()
	if _, err := s.db.Exec(`DELETE FROM user_mitigations`); err != nil {
		t.Fatalf("empty user_mitigations: %v", err)
	}
	if s.unmitigatedCache != nil {
		s.unmitigatedCache.Purge()
	}
	if s.userMitigationCache != nil {
		s.userMitigationCache.Purge()
	}
}

// A fingerprint block is a client class on one network (ADR 0026). These pin
// the store's half: how evidence accumulates towards a block, what a block
// written before the change does, how a class is released, and that the table
// the scoping multiplies stays bounded.

const (
	scopeChrome       = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	scopeChromeNoRef  = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cn0200_7e33b58890ac"
	scopeOtherBrowser = "t13d1715h2_5b57614c22b0_3d5424432f57_ge11cr0200_7e33b58890ac"
)

// Evidence counts towards a block for mitigationEvidenceWindow from its first
// piece. A count that never lapsed turned three false positives days apart
// into a block.
func TestEvidenceTowardsAFingerprintBlockLapses(t *testing.T) {
	ResetFingerprintSightings()
	t.Cleanup(ResetFingerprintSightings)
	const ip = "203.0.113.7"
	key := repid.For(scopeChrome, ip)
	start := time.Now()

	shouldMitigateFingerprint(key, ip, start)
	shouldMitigateFingerprint(key, ip, start.Add(time.Minute))
	if ok, _ := shouldMitigateFingerprint(key, ip, start.Add(mitigationEvidenceWindow+time.Second)); ok {
		t.Error("three pieces of evidence spread wider than the window added up to a block")
	}
	// That third piece opened a window of its own.
	shouldMitigateFingerprint(key, ip, start.Add(mitigationEvidenceWindow+2*time.Second))
	if ok, reason := shouldMitigateFingerprint(key, ip, start.Add(mitigationEvidenceWindow+3*time.Second)); !ok {
		t.Errorf("three pieces within one window did not earn a block: %s", reason)
	}
}

// Evidence is counted per class and network: an attack on one network is not
// evidence against the same browser build on another.
func TestEvidenceIsCountedPerNetwork(t *testing.T) {
	ResetFingerprintSightings()
	t.Cleanup(ResetFingerprintSightings)
	now := time.Now()
	for i, ip := range []string{"203.0.113.7", "198.51.100.7"} {
		if ok, _ := shouldMitigateFingerprint(repid.For(scopeChrome, ip), ip, now.Add(time.Duration(i)*time.Second)); ok {
			t.Fatalf("one piece of evidence blocked %s", ip)
		}
	}
	if ok, _ := shouldMitigateFingerprint(repid.For(scopeChrome, "192.0.2.7"), "192.0.2.7", now); ok {
		t.Error("evidence from two other networks counted towards a block on a third")
	}
}

// Every block was keyed on a bare fingerprint before ADR 0026. The network was
// never recorded, so such a row cannot be moved to a scoped key; it names a
// client build on every network, so it is not enforced, not listed, and not
// written again.
func TestAnUnscopedFingerprintBlockIsNeitherEnforcedNorListedNorWritten(t *testing.T) {
	onEachEngine(t, assertUnscopedBlockIsInert)
}

func assertUnscopedBlockIsInert(t *testing.T) {
	s := getStore()
	if _, err := s.db.Exec(s.dialect.Rebind(`INSERT INTO user_mitigations
		(fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, updated_at)
		VALUES (?, '', 'JA4+', 'mitigated', 'written before ADR 0026', 'waf', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`),
		scopeChrome); err != nil {
		t.Fatalf("seed a legacy block: %v", err)
	}
	// A shared Postgres keeps the row after the test; a later test that lists
	// or preloads fingerprint blocks would read it.
	t.Cleanup(func() {
		_, _ = s.db.Exec(s.dialect.Rebind(`DELETE FROM user_mitigations WHERE fingerprint = ?`), scopeChrome)
	})

	if IsUserMitigated(scopeChrome) {
		t.Error("a block on a bare fingerprint, which names a client build on every network, is enforced")
	}
	if rows, total := GetUserMitigations(t.Context(), 50, 0); total != 0 || len(rows) != 0 {
		t.Errorf("the legacy block is listed as a mitigation in force (%d rows, total %d)", len(rows), total)
	}
	if rows, total := GetCombinedMitigations(t.Context(), 50, 0); total != 0 || len(rows) != 0 {
		t.Errorf("the legacy block is on the combined list (%d rows, total %d)", len(rows), total)
	}

	MarkUserMitigated(scopeOtherBrowser, "JA4+", "unscoped write", "waf")
	var n int
	if err := s.db.QueryRow(s.dialect.Rebind(`SELECT COUNT(*) FROM user_mitigations WHERE fingerprint = ?`),
		scopeOtherBrowser).Scan(&n); err != nil || n != 0 {
		t.Errorf("a block on a bare fingerprint was written (%d rows, err %v)", n, err)
	}
}

// A release that names a fingerprint -- a threat's JA4+ -- releases its class
// on every network it is blocked on, and nothing else, and holds the class so
// the next piece of evidence does not undo the operator.
func TestReleasingAClassReleasesEveryNetworkAndHoldsTheClass(t *testing.T) {
	onEachEngine(t, assertClassReleaseReachesEveryNetwork)
}

func assertClassReleaseReachesEveryNetwork(t *testing.T) {
	onA, onB := repid.For(scopeChrome, "203.0.113.7"), repid.For(scopeChrome, "198.51.100.7")
	other := repid.For(scopeOtherBrowser, "203.0.113.7")
	for _, key := range []string{onA, onB, other} {
		MarkUserMitigated(key, "JA4+", "blocked", "waf")
	}

	// Named by the other request of the same browser: same class.
	if !ReleaseUserMitigationClass(scopeChromeNoRef) {
		t.Fatal("releasing a class that is blocked on two networks reported releasing nothing")
	}
	if IsUserMitigated(onA) || IsUserMitigated(onB) {
		t.Errorf("the class is still blocked (203.0.113: %v, 198.51.100: %v)", IsUserMitigated(onA), IsUserMitigated(onB))
	}
	if !IsUserMitigated(other) {
		t.Error("releasing one browser build released another's block")
	}
	if !userMitigationHeld(repid.For(scopeChrome, "192.0.2.9")) {
		t.Error("the released class is not held on a network it was not blocked on, so the next " +
			"evidence there would block it again straight after the operator released it")
	}
	if ReleaseUserMitigationClass(scopeChrome) {
		t.Error("a repeat release reported releasing a block")
	}
}

// Scoping makes a row per class and network. Rows past both the block's TTL
// and a release's hold decide nothing and are pruned; rows inside them are
// kept.
func TestPruneKeepsOnlyFingerprintBlocksThatStillDecideSomething(t *testing.T) {
	onEachEngine(t, assertPruneKeepsLiveBlocks)
}

func assertPruneKeepsLiveBlocks(t *testing.T) {
	s := getStore()
	stale, live := repid.For(scopeChrome, "203.0.113.7"), repid.For(scopeChrome, "198.51.100.7")
	staleHold, liveHold := repid.Class(scopeOtherBrowser), repid.For(scopeOtherBrowser, "192.0.2.7")
	MarkUserMitigated(stale, "JA4+", "blocked", "waf")
	MarkUserMitigated(live, "JA4+", "blocked", "waf")
	MarkUserUnmitigated(staleHold)
	MarkUserUnmitigated(liveHold)

	age := func(by time.Duration, keys ...string) {
		t.Helper()
		at := time.Now().UTC().Add(-by).Format(threatTimestampLayout)
		for _, key := range keys {
			if _, err := s.db.Exec(s.dialect.Rebind(`UPDATE user_mitigations SET updated_at = ? WHERE fingerprint = ?`),
				at, key); err != nil {
				t.Fatalf("age %s: %v", key, err)
			}
		}
	}
	age(userMitigationRetention()+time.Hour, stale, staleHold)
	// Past a block's TTL, well inside a release's hold: the hold still decides.
	age(mitigationTTL+time.Hour, liveHold)
	s.pruneUserMitigations(t.Context())

	for key, want := range map[string]int{stale: 0, staleHold: 0, live: 1, liveHold: 1} {
		var n int
		if err := s.db.QueryRow(s.dialect.Rebind(`SELECT COUNT(*) FROM user_mitigations WHERE fingerprint = ?`),
			key).Scan(&n); err != nil || n != want {
			t.Errorf("%s: %d rows after pruning (err %v), want %d", key, n, err, want)
		}
	}
}
