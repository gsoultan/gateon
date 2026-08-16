// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// GetReputation runs per request on the metrics path and was rewritten to take
// the shard's read lock on the common path, upgrading to the write lock only for
// the idle-time recovery. These tests pin the behaviour that rewrite must
// preserve — they pass against both the original write-locked version and the
// current one, which is the point: they describe the contract, not the
// implementation.
//
// Entries are seeded straight into the shard rather than through
// DecreaseReputation, which no-ops under GATEON_TEST unless
// GATEON_ENABLE_TEST_REPUTATION is also set, and which stamps LastEvent with
// time.Now() — leaving no way to exercise recovery without sleeping.
func seedReputation(t *testing.T, fingerprint string, r *Reputation) {
	t.Helper()
	shard := getRepShard(fingerprint)
	shard.mu.Lock()
	shard.cache.Add(fingerprint, r)
	shard.mu.Unlock()
	t.Cleanup(func() {
		shard.mu.Lock()
		shard.cache.Remove(fingerprint)
		shard.mu.Unlock()
	})
}

func TestGetReputation_UnknownFingerprintIsNeutral(t *testing.T) {
	if got := GetReputation("no-such-fingerprint-b7c1"); got != 100 {
		t.Fatalf("GetReputation = %v, want 100 for an unknown client", got)
	}
	if got := GetReputation(""); got != 100 {
		t.Fatalf("GetReputation(\"\") = %v, want 100", got)
	}
}

// A recently-active client reads back its stored score untouched. This is the
// path that now holds only a read lock, so it is also the one most likely to
// return something stale or wrong if the split were done carelessly.
func TestGetReputation_RecentEntryReturnsStoredScore(t *testing.T) {
	const fp = "rep-recent-a1"
	seedReputation(t, fp, &Reputation{
		Score:        42.5,
		LastEvent:    time.Now().Add(-5 * time.Minute),
		RecoveryRate: 1.0,
	})

	if got := GetReputation(fp); got != 42.5 {
		t.Fatalf("GetReputation = %v, want the stored 42.5", got)
	}

	// And the read must not have mutated it.
	if got := GetReputation(fp); got != 42.5 {
		t.Fatalf("second GetReputation = %v; a read changed the score", got)
	}
}

// Idle longer than an hour recovers at RecoveryRate points per hour. This is
// the branch that still takes the write lock.
func TestGetReputation_RecoversAfterIdleHours(t *testing.T) {
	const fp = "rep-idle-c3"
	seedReputation(t, fp, &Reputation{
		Score:        50,
		LastEvent:    time.Now().Add(-4 * time.Hour),
		RecoveryRate: 2.0,
	})

	got := GetReputation(fp)

	// 50 + 4h * 2.0/h = 58, allowing for the fraction of an hour that elapses
	// between seeding and reading.
	if got < 57.9 || got > 58.2 {
		t.Fatalf("GetReputation = %v, want ~58 after 4 idle hours at 2.0/hour", got)
	}
	if got <= 50 {
		t.Fatalf("GetReputation = %v; the score did not recover at all", got)
	}
}

// Recovery is capped at 100: a long-idle client becomes neutral, never better.
func TestGetReputation_RecoveryCapsAt100(t *testing.T) {
	const fp = "rep-verylong-d4"
	seedReputation(t, fp, &Reputation{
		Score:        90,
		LastEvent:    time.Now().Add(-500 * time.Hour),
		RecoveryRate: 1.0,
	})

	if got := GetReputation(fp); got != 100 {
		t.Fatalf("GetReputation = %v, want the 100 ceiling", got)
	}
}

// Past 24 idle hours the violation count resets, so a client that stopped
// misbehaving is not penalised by adaptive penalties forever.
func TestGetReputation_ResetsViolationsAfter24Hours(t *testing.T) {
	const fp = "rep-reset-e5"
	seedReputation(t, fp, &Reputation{
		Score:          80,
		LastEvent:      time.Now().Add(-30 * time.Hour),
		RecoveryRate:   1.0,
		ViolationCount: 7,
	})

	GetReputation(fp)

	shard := getRepShard(fp)
	shard.mu.RLock()
	val, ok := shard.cache.Peek(fp)
	shard.mu.RUnlock()
	if !ok {
		t.Fatal("entry vanished")
	}
	if n := val.(*Reputation).ViolationCount; n != 0 {
		t.Fatalf("ViolationCount = %d, want 0 after 30 idle hours", n)
	}
}

// A zero RecoveryRate must not freeze a client at its penalised score; the
// documented default is 1.0 point per hour.
func TestGetReputation_ZeroRateFallsBackToDefault(t *testing.T) {
	const fp = "rep-zerorate-f6"
	seedReputation(t, fp, &Reputation{
		Score:        10,
		LastEvent:    time.Now().Add(-3 * time.Hour),
		RecoveryRate: 0,
	})

	if got := GetReputation(fp); got < 12.9 || got > 13.2 {
		t.Fatalf("GetReputation = %v, want ~13 (10 + 3h at the 1.0/hour default)", got)
	}
}

// The read path is lock-split, so concurrent readers and the recovery writer
// must not race. Run with -race for this to mean anything.
func TestGetReputation_ConcurrentReadsAndRecovery(t *testing.T) {
	const readers = 24
	for i := range 8 {
		seedReputation(t, fmt.Sprintf("rep-conc-%d", i), &Reputation{
			Score:        60,
			LastEvent:    time.Now().Add(-2 * time.Hour), // forces the write-lock branch
			RecoveryRate: 1.0,
		})
	}

	var wg sync.WaitGroup
	for r := range readers {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := range 200 {
				fp := fmt.Sprintf("rep-conc-%d", (r+i)%8)
				if got := GetReputation(fp); got < 0 || got > 100 {
					t.Errorf("GetReputation = %v, out of range", got)
					return
				}
			}
		}(r)
	}
	wg.Wait()
}
