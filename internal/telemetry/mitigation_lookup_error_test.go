// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// breakTable makes every query against table fail until the returned func
// puts it back: the shape of a Postgres failover, an exhausted pool or a
// SQLITE_BUSY past the busy timeout, as the enforcement lookups see it.
func breakTable(t *testing.T, table string) (restore func()) {
	t.Helper()
	s := getStore()
	if _, err := s.db.Exec(`ALTER TABLE ` + table + ` RENAME TO ` + table + `_offline`); err != nil {
		t.Fatalf("take %s offline: %v", table, err)
	}
	restored := false
	restore = func() {
		if restored {
			return
		}
		restored = true
		if _, err := s.db.Exec(`ALTER TABLE ` + table + `_offline RENAME TO ` + table); err != nil {
			t.Fatalf("bring %s back: %v", table, err)
		}
	}
	t.Cleanup(restore)
	return restore
}

// A failed lookup was cached as "not shunned", with no expiry, so a blocked
// address was served during the outage and went on being served after the
// database recovered, until the entry happened to be evicted (2026-10-02
// dataplane F3). An error is now never cached: the next lookup after recovery
// reads the block (ADR 0043).
func TestAnAddressLookupThatFailsIsNotCachedAsNotShunned(t *testing.T) {
	freshStore(t)
	const ip = "198.51.100.77"
	if err := MarkIPMitigated(ip, "operator block"); err != nil {
		t.Fatal(err)
	}
	purgeShunCache() // a restart, or the entry evicted: the cache has no answer
	restore := breakTable(t, "ip_mitigations")
	_ = IsIPMitigated(ip) // during the outage, whatever it answers
	restore()
	if !IsIPMitigated(ip) {
		t.Fatal("after the database recovered, a blocked address still read as not shunned")
	}
}

// A block the cache already holds is not undone by a failed lookup either.
func TestAKnownShunStaysEnforcedDuringAnOutage(t *testing.T) {
	freshStore(t)
	const ip = "198.51.100.78"
	if err := MarkIPMitigated(ip, "operator block"); err != nil {
		t.Fatal(err)
	}
	if !IsIPMitigated(ip) {
		t.Fatal("not shunned before the outage")
	}
	breakTable(t, "ip_mitigations")
	if !IsIPMitigated(ip) {
		t.Fatal("a cached block stopped being enforced during an outage")
	}
}

// A "not shunned" answer is trusted for a bounded time, not forever: a block
// written by another node -- or straight to the database -- is enforced here
// once the answer ages out.
func TestANotShunnedAnswerIsReadAgainOnceItAgesOut(t *testing.T) {
	freshStore(t)
	const ip = "198.51.100.79"
	if IsIPMitigated(ip) {
		t.Fatal("shunned before anything was written")
	}
	// Another node's block: the row, without this node's cache.
	s := getStore()
	if _, err := s.db.Exec(s.dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, updated_at)
		VALUES (?, 'mitigated', 'other node', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`), ip); err != nil {
		t.Fatal(err)
	}
	ageNegativeAnswers(t, ip)
	if !IsIPMitigated(ip) {
		t.Fatal("a block written elsewhere was not enforced once the cached answer aged out")
	}
}

// ageNegativeAnswers rewrites key's cached "not blocked" answer as one read two
// epochs ago, which is what the passage of two mitigationEpochLength does.
func ageNegativeAnswers(t *testing.T, key string) {
	t.Helper()
	s := getStore()
	stale := notBlockedUntil(mitigationEpoch.Load() - 2)
	for _, c := range []interface {
		Peek(key any) (any, bool)
		Add(key, value any)
	}{s.unmitigatedCache, s.userMitigationCache} {
		if v, ok := c.Peek(key); ok {
			if _, isNegative := v.(notBlockedUntil); !isNegative {
				t.Fatalf("cached answer for %s is %T, want a not-blocked answer", key, v)
			}
			c.Add(key, stale)
			return
		}
	}
	t.Fatalf("no cached answer for %s", key)
}

// The fingerprint block has the same shape: a failed lookup answered "not
// blocked" and cached it, over the block the cache held.
func TestAFingerprintLookupThatFailsDoesNotTurnABlockOff(t *testing.T) {
	freshStore(t)
	key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.80")
	MarkUserMitigated(key, "JA4+", "test", "waf")
	if !IsUserMitigated(key) {
		t.Fatal("not blocked before the outage")
	}
	restore := breakTable(t, "user_mitigations")
	if !IsUserMitigated(key) {
		t.Error("a known fingerprint block stopped being enforced during an outage")
	}
	restore()
	if !IsUserMitigated(key) {
		t.Fatal("after the database recovered, a blocked fingerprint read as not blocked")
	}
}

// A fingerprint released by an operator and blocked again is blocked: the
// release override the cache keeps used to outlive the new block, so
// IsUserMitigated answered "released" until the entry was evicted.
func TestAFingerprintBlockedAgainAfterAReleaseIsBlocked(t *testing.T) {
	freshStore(t)
	key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.81")
	MarkUserMitigated(key, "JA4+", "test", "waf")
	MarkUserUnmitigated(key)
	if IsUserMitigated(key) {
		t.Fatal("still blocked after the release")
	}
	// A minute passes: within one second the release wins the tie on purpose.
	if _, err := getStore().db.Exec(`UPDATE user_mitigations SET updated_at = datetime('now', '-1 minute')
		WHERE fingerprint = ? AND status = 'unmitigated'`, key); err != nil {
		t.Fatal(err)
	}
	MarkUserMitigated(key, "JA4+", "operator blocked it again", "manual")
	if !IsUserMitigated(key) {
		t.Fatal("a block made after a release is not enforced")
	}
}

// A fingerprint's "not blocked" answer ages out as an address's does.
func TestAFingerprintNotBlockedAnswerIsReadAgainOnceItAgesOut(t *testing.T) {
	freshStore(t)
	key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.82")
	if IsUserMitigated(key) {
		t.Fatal("blocked before anything was written")
	}
	s := getStore()
	if _, err := s.db.Exec(s.dialect.Rebind(`INSERT INTO user_mitigations (fingerprint, ja4h, fp_type, status, reason, category, mitigated_at, updated_at)
		VALUES (?, '', 'JA4+', 'mitigated', 'other node', 'waf', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`), key); err != nil {
		t.Fatal(err)
	}
	ageNegativeAnswers(t, key)
	if !IsUserMitigated(key) {
		t.Fatal("a fingerprint block written elsewhere was not enforced once the cached answer aged out")
	}
}
