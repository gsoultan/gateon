// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"math"
	"strings"
	"testing"
)

// ApplyRemoteReputation is fed by the gossip delegate. memberlist encrypts and
// authenticates every message, so the sender is a cluster peer rather than
// anyone on the network -- but a peer is still a different process, possibly a
// different version, possibly with corrupted state. DecreaseReputation clamps
// the score at zero and trims history to five entries; this path applied
// neither, so the one value that arrives from somewhere else was the one value
// no bound was maintained for.

func TestSanitiseRemoteReputationClampsScore(t *testing.T) {
	cases := []struct {
		name  string
		score float64
		want  float64
	}{
		// The branch in ApplyRemoteReputation takes any score >= 100
		// unconditionally, so an unclamped 1e308 makes that client's
		// reputation unbeatable by any local penalty -- it is never blocked
		// again.
		{"absurdly high", 1e308, neutralReputationScore},
		{"just above neutral", 100.5, neutralReputationScore},
		{"negative", -50, 0},
		// Every comparison against NaN is false, so a NaN score is a client no
		// threshold ever catches.
		{"NaN", math.NaN(), neutralReputationScore},
		{"in range is untouched", 42.5, 42.5},
		{"zero is untouched", 0, 0},
		{"neutral is untouched", neutralReputationScore, neutralReputationScore},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := sanitiseRemoteReputation(tc.score, 0, nil)
			if got != tc.want {
				t.Errorf("score %v sanitised to %v, want %v", tc.score, got, tc.want)
			}
		})
	}
}

// RecoveryRate is 1/(1 + violations/5), which divides by zero at exactly -5.
func TestSanitiseRemoteReputationRejectsNegativeViolations(t *testing.T) {
	_, got, _ := sanitiseRemoteReputation(50, -5, nil)
	if got != 0 {
		t.Fatalf("violations = %d, want 0", got)
	}

	// The arithmetic the value feeds, asserted directly: the reason -5 matters
	// is not that it is odd, it is that it is a division by zero.
	rate := 1.0 / (1.0 + float64(got)/5.0)
	if math.IsInf(rate, 0) || math.IsNaN(rate) {
		t.Errorf("RecoveryRate computed to %v from sanitised violations", rate)
	}
}

func TestSanitiseRemoteReputationBoundsHistory(t *testing.T) {
	long := make([]string, 200)
	for i := range long {
		long[i] = strings.Repeat("x", 4096)
	}

	_, _, got := sanitiseRemoteReputation(50, 0, long)

	if len(got) > maxReputationHistory {
		t.Errorf("history kept %d entries, want at most %d; DecreaseReputation "+
			"trims to that bound and says it does so to avoid unbounded growth",
			len(got), maxReputationHistory)
	}
	for i, h := range got {
		if len(h) > maxReputationHistoryEntry+1 {
			t.Errorf("history entry %d is %d bytes, want at most %d; the count "+
				"bound says nothing about how large each one is",
				i, len(h), maxReputationHistoryEntry+1)
		}
	}
}

// TestApplyRemoteReputationCannotRaiseAClientAboveNeutral drives the property
// through the exported function, so it covers the wiring and not only the
// helper: a peer must not be able to hand a penalised client a score that no
// local penalty can reach.
func TestApplyRemoteReputationCannotRaiseAClientAboveNeutral(t *testing.T) {
	t.Setenv("GATEON_TEST", "")
	const fp = "t13d1516h2_remote_reputation_test"
	t.Cleanup(func() { ResetReputation(fp) })

	ApplyRemoteReputation(fp, 1e308, 0, nil)

	if got := GetReputation(fp); got > neutralReputationScore {
		t.Errorf("a peer set this client's reputation to %v; above %v no local "+
			"penalty brings it back into blocking range", got, neutralReputationScore)
	}
}
