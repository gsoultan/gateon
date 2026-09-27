// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// The RL limiter became the only path from a detector's finding to a kernel
// limit when the diagnostics loop's own throttle was removed (2026-09-27). These
// are the properties that path has to have.

// passes feeds rl one observation of ip at score per analysis pass, a minute
// apart, starting at base.
func passes(rl *ReinforcementLearningLimiter, ip string, score float64, n int, base time.Time) time.Time {
	at := base
	for range n {
		rl.now = func() time.Time { return at }
		rl.ProcessFeedback(ip, score)
		at = at.Add(time.Minute)
	}
	return at
}

// TestAHigherThreatNeverGetsALooserLimit: the kernel earns an address one
// packet per interval, and the table gave a score above 0.9 a 10ms interval and
// a score above 0.4 a 200ms one -- the most dangerous addresses twenty times
// the packets of the least.
func TestAHigherThreatNeverGetsALooserLimit(t *testing.T) {
	previous := time.Duration(0)
	for _, q := range []float64{0.45, 0.75, 0.95} {
		interval := adaptiveInterval(q)
		if interval <= previous {
			t.Errorf("score %.2f allows %.0f packets a second, no fewer than the %.0f a lower score allows",
				q, time.Second.Seconds()/interval.Seconds(), time.Second.Seconds()/previous.Seconds())
		}
		previous = interval
	}
}

// TestNoSingleFindingLimitsAnAddress: the loop's own throttle limited an
// address the first time a finding named it. Findings on two passes are not
// enough either; the third, a minute later, is.
func TestNoSingleFindingLimitsAnAddress(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)
	const ip = "198.51.100.20"
	next := passes(rl, ip, 1.0, 2, time.Unix(1_700_000_000, 0))
	if d, limited := mgr.limitFor(ip); limited {
		t.Fatalf("limited to one packet per %v after findings on two passes", d)
	}
	passes(rl, ip, 1.0, 1, next)
	if _, limited := mgr.limitFor(ip); !limited {
		t.Fatalf("not limited after findings on three consecutive passes")
	}
}

// TestAllowlistedAddressesAreNeverLimited: GATEON_MITIGATION_ALLOWLIST is
// "never mitigated", and an address allowlisted after it was limited is let
// go on its next finding.
func TestAllowlistedAddressesAreNeverLimited(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)
	const ip = "198.51.100.21"
	next := passes(rl, ip, 1.0, 10, time.Unix(1_700_000_000, 0))
	if _, limited := mgr.limitFor(ip); !limited {
		t.Fatalf("precondition: ten passes of findings did not limit %s", ip)
	}

	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix(ip + "/32")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	passes(rl, ip, 1.0, 10, next)
	if d, limited := mgr.limitFor(ip); limited {
		t.Errorf("allowlisted %s is limited to one packet per %v", ip, d)
	}
	if rl.Len() != 0 {
		t.Errorf("the limiter still keeps a history for an allowlisted address")
	}
}

// TestForgetLiftsTheLimitAndTheHistory: an operator releases an address. The
// limit goes, and so does the score that earned it -- kept, it would limit the
// address again on the very next pass.
func TestForgetLiftsTheLimitAndTheHistory(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)
	const ip = "198.51.100.22"
	next := passes(rl, ip, 1.0, 10, time.Unix(1_700_000_000, 0))

	rl.Forget(ip)
	if _, limited := mgr.limitFor(ip); limited || mgr.clearCount(ip) == 0 {
		t.Fatalf("after Forget the limit is still in place (clears issued: %d)", mgr.clearCount(ip))
	}
	next = passes(rl, ip, 1.0, 2, next)
	if d, limited := mgr.limitFor(ip); limited {
		t.Fatalf("limited again (one packet per %v) within two passes of being released", d)
	}
	passes(rl, ip, 1.0, 1, next)
	if _, limited := mgr.limitFor(ip); !limited {
		t.Errorf("findings on three passes after the release did not limit it again")
	}
}

// TestIPv6AddressesInOneSlash64ShareAHistory: the kernel limits IPv6 by /64,
// so the history is kept per /64 -- an attacker walking its /64 is one entry,
// and releasing any address in it releases the entry that was limited.
func TestIPv6AddressesInOneSlash64ShareAHistory(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)
	at := time.Unix(1_700_000_000, 0)
	for i := range 3 {
		rl.now = func() time.Time { return at }
		rl.ProcessFeedback("2001:db8:5:6::"+string(rune('a'+i)), 1.0)
		at = at.Add(time.Minute)
	}
	if rl.Len() != 1 {
		t.Fatalf("three addresses in one /64 hold %d histories, want 1", rl.Len())
	}
	if _, limited := mgr.limitFor("2001:db8:5:6::"); !limited {
		t.Fatalf("three findings in one /64 did not limit the /64")
	}
	rl.Forget("2001:db8:5:6::ffff")
	if _, limited := mgr.limitFor("2001:db8:5:6::"); limited || rl.Len() != 0 {
		t.Errorf("releasing an address in the /64 left the /64 limited")
	}
}
