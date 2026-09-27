// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// blockerRefusesBelow is the score under which the reputation blocker refuses
// (middleware/security/identity), restated here because this package cannot
// import the blocker.
const blockerRefusesBelow = 2.0

// backdateReputation moves key's last event d into the past, as if the client
// had been idle that long.
func backdateReputation(t *testing.T, key string, d time.Duration) {
	t.Helper()
	shard := getRepShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	val, ok := shard.cache.Peek(key)
	if !ok {
		t.Fatalf("setup: no reputation recorded for %s", key)
	}
	r, isRep := val.(*Reputation)
	if !isRep {
		t.Fatalf("setup: %s holds %T", key, val)
	}
	r.LastEvent = r.LastEvent.Add(-d)
}

// runCollector does what the ten-second system metrics collector does to
// reputation, now rather than when its rate limit next allows.
func runCollector() {
	lastMetricsUpdate.Store(0)
	UpdateReputationMetrics()
}

// TestARefusedClientRecoversWhileIdle pins the recovery the reputation blocker
// actually depends on.
//
// The blocker reads GetReputationScore, which never applies recovery; the only
// thing that raises an idle client's score on that path is the metrics
// collector's pass over the dirty set. The existing recovery tests seed
// hand-built entries and call GetReputation, which the blocker does not call,
// so the collector's recovery, the recovery rate DecreaseReputation assigns and
// the clamp at zero could each be deleted without a test noticing -- and any
// of those turns "self-healing" (doc/siem-correlation.md) into a block that
// never lifts.
func TestARefusedClientRecoversWhileIdle(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	const key = "t13d_recovery_path|203.0.113"
	t.Cleanup(func() { ResetReputation(key) })

	for range 5 {
		DecreaseReputation(key, 50, "waf_blocked")
	}
	if got := GetReputationScore(key); got != 0 {
		t.Fatalf("five blocks left the score at %v; it is clamped at 0, or recovery "+
			"has to climb out of a debt no threshold was sized for", got)
	}

	// Five violations slow recovery to 1/(1+5/5) = half a point an hour, so
	// six idle hours are worth three points: out of refusal, not back to
	// trusted.
	backdateReputation(t, key, 6*time.Hour)
	runCollector()
	got := GetReputationScore(key)
	if got < blockerRefusesBelow {
		t.Fatalf("after six idle hours the score the blocker reads is %v, still under the %v "+
			"it refuses at: the block does not lift on its own", got, blockerRefusesBelow)
	}
	if got > 5 {
		t.Errorf("after six idle hours the score is %v; five violations should hold recovery "+
			"to half a point an hour", got)
	}
}

// TestRepeatedViolationsCostMore pins the adaptive penalty DecreaseReputation
// documents: a repeat offence costs more than a first one.
func TestRepeatedViolationsCostMore(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	const key = "t13d_adaptive_penalty|198.51.100"
	t.Cleanup(func() { ResetReputation(key) })

	DecreaseReputation(key, 20, "rate_limit")
	first := 100 - GetReputationScore(key)
	DecreaseReputation(key, 20, "rate_limit")
	second := 100 - GetReputationScore(key) - first
	if second <= first {
		t.Fatalf("the second identical violation cost %v and the first %v; a repeat "+
			"offence is documented to cost more", second, first)
	}
}

// TestLocalHistoryIsBounded pins the five-entry cap on a locally grown history,
// the bound the remote path is already held to.
func TestLocalHistoryIsBounded(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	const key = "t13d_history_bound|192.0.2"
	t.Cleanup(func() { ResetReputation(key) })

	for range 50 {
		DecreaseReputation(key, 0.001, "rate_limit")
	}
	for _, rec := range GetWorstReputations(1000) {
		if rec.Fingerprint != key {
			continue
		}
		if len(rec.History) > maxReputationHistory {
			t.Fatalf("history holds %d entries after 50 violations, want at most %d",
				len(rec.History), maxReputationHistory)
		}
		return
	}
	t.Fatalf("setup: %s is not among the recorded reputations", key)
}

// TestAPeerCannotRaiseALocallyLoweredScore pins the rule ApplyRemoteReputation
// states: a peer's score is taken only when it is worse than ours, or a reset.
// Taking any score would let a peer that simply had not seen the attack yet --
// or had a stale entry -- unblock a client this node had just caught.
func TestAPeerCannotRaiseALocallyLoweredScore(t *testing.T) {
	const key = "t13d_remote_rule|203.0.113"
	t.Cleanup(func() { ResetReputation(key) })

	ApplyRemoteReputation(key, 10, 4, []string{"waf_blocked"})
	ApplyRemoteReputation(key, 60, 1, []string{"rate_limit"})
	if got := GetReputationScore(key); got != 10 {
		t.Fatalf("a peer's 60 replaced this node's 10 (now %v); only a worse score or a "+
			"reset may", got)
	}
	ApplyRemoteReputation(key, 100, 0, []string{"Manual reset"})
	if got := GetReputationScore(key); got != 100 {
		t.Fatalf("a peer's reset left the score at %v", got)
	}
}
