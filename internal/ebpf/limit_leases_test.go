// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// limitRecorder is a Manager that records which adaptive limits are in force,
// the way the kernel map holds them, so a test can see what the Holder left
// behind.
type limitRecorder struct {
	stubManager
	limits    map[string]time.Duration
	cleared   []string
	failSet   bool
	failClear int // fail this many ClearAdaptiveRateLimit calls, then succeed
}

func newLimitRecorder() *limitRecorder {
	return &limitRecorder{limits: map[string]time.Duration{}}
}

func (r *limitRecorder) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	if r.failSet {
		return errors.New("adaptive_limits: map full")
	}
	key, _ := leaseKey(ip)
	r.limits[key] = interval
	return nil
}

func (r *limitRecorder) ClearAdaptiveRateLimit(ip string) error {
	if r.failClear > 0 {
		r.failClear--
		return errors.New("transient")
	}
	key, _ := leaseKey(ip)
	delete(r.limits, key)
	r.cleared = append(r.cleared, ip)
	return nil
}

func newLeasedHolder(m Manager) (*Holder, *time.Time) {
	now := time.Unix(1_700_000_000, 0)
	h := NewHolder(m)
	h.now = func() time.Time { return now }
	return h, &now
}

// TestAnAdaptiveLimitLapsesWhenNotRenewed: every writer but the RL limiter
// set limits and never cleared them, so a limit lasted as long as the eBPF
// manager -- one WAF hit from a shared address throttled everyone behind it
// until the process restarted.
func TestAnAdaptiveLimitLapsesWhenNotRenewed(t *testing.T) {
	rec := newLimitRecorder()
	h, now := newLeasedHolder(rec)
	if err := h.SetAdaptiveRateLimit("198.51.100.7", time.Second); err != nil {
		t.Fatal(err)
	}

	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease - time.Second))
	if _, ok := rec.limits["198.51.100.7"]; !ok {
		t.Fatal("the limit was lifted before its lease ran out")
	}
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	if _, ok := rec.limits["198.51.100.7"]; ok {
		t.Fatalf("the limit is still in force %v after it was last set", AdaptiveLimitLease)
	}
}

// TestSettingALimitAgainRenewsIt: a writer whose reason persists keeps its
// limit by setting it again.
func TestSettingALimitAgainRenewsIt(t *testing.T) {
	rec := newLimitRecorder()
	h, now := newLeasedHolder(rec)
	_ = h.SetAdaptiveRateLimit("198.51.100.7", time.Second)
	*now = now.Add(4 * time.Minute)
	_ = h.SetAdaptiveRateLimit("198.51.100.7", time.Second)

	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease - time.Second))
	if _, ok := rec.limits["198.51.100.7"]; !ok {
		t.Fatal("a renewed limit was lifted on the first lease's schedule")
	}
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	if _, ok := rec.limits["198.51.100.7"]; ok {
		t.Fatal("a renewed limit outlived its renewed lease")
	}
}

// TestIPv6LimitsAreLeasedPerSlash64: the kernel keeps one IPv6 entry per /64,
// so the leases must too -- keyed by address, an attacker rotating through
// its /64 grows the lease table without bound while the kernel map holds one
// entry.
func TestIPv6LimitsAreLeasedPerSlash64(t *testing.T) {
	rec := newLimitRecorder()
	h, now := newLeasedHolder(rec)
	for i := range 5000 {
		_ = h.SetAdaptiveRateLimit(fmt.Sprintf("2001:db8:1:2::%x", i+1), time.Second)
	}
	if n := len(h.leases.entries); n != 1 {
		t.Fatalf("5000 addresses in one /64 hold %d leases, want 1", n)
	}
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	if len(rec.limits) != 0 || !slices.Equal(rec.cleared, []string{"2001:db8:1:2::"}) {
		t.Fatalf("after expiry: limits %v, released %v; want none left, the /64 released once", rec.limits, rec.cleared)
	}
}

// TestALimitTheKernelRefusedTakesNoLease: only limits that reached the kernel
// are leased, which is what bounds the lease table by the kernel map.
func TestALimitTheKernelRefusedTakesNoLease(t *testing.T) {
	rec := newLimitRecorder()
	rec.failSet = true
	h, _ := newLeasedHolder(rec)
	if err := h.SetAdaptiveRateLimit("198.51.100.7", time.Second); err == nil {
		t.Fatal("the kernel's refusal was not reported")
	}
	if n := len(h.leases.entries); n != 0 {
		t.Fatalf("a refused limit holds %d leases, want 0", n)
	}
}

// TestAFailedReleaseIsRetried: a lease dropped on a failed release is a limit
// nothing will ever lift again.
func TestAFailedReleaseIsRetried(t *testing.T) {
	rec := newLimitRecorder()
	rec.failClear = 1
	h, now := newLeasedHolder(rec)
	_ = h.SetAdaptiveRateLimit("198.51.100.7", time.Second)

	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease + 30*time.Second))
	if _, ok := rec.limits["198.51.100.7"]; ok {
		t.Fatal("the limit was never lifted after one failed release")
	}
}

// TestAClearedLimitIsNotReleasedAgain and TestSwapForgetsLeases keep the
// table to limits that are actually in force.
func TestAClearedLimitIsNotReleasedAgain(t *testing.T) {
	rec := newLimitRecorder()
	h, now := newLeasedHolder(rec)
	_ = h.SetAdaptiveRateLimit("198.51.100.7", time.Second)
	_ = h.ClearAdaptiveRateLimit("198.51.100.7")
	rec.cleared = nil

	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	if len(rec.cleared) != 0 {
		t.Fatalf("a limit already cleared was released again: %v", rec.cleared)
	}
}

func TestSwapForgetsLeases(t *testing.T) {
	old := newLimitRecorder()
	h, now := newLeasedHolder(old)
	_ = h.SetAdaptiveRateLimit("198.51.100.7", time.Second)

	fresh := newLimitRecorder()
	h.Swap(fresh)
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease))
	if len(fresh.cleared) != 0 {
		t.Fatalf("the new manager was asked to release a limit it never had: %v", fresh.cleared)
	}
}

// TestAdaptiveLimitsListWhatIsInForce: the table the dashboard lists as kernel
// throttles -- key, rate, reason, expiry -- newest first, and only what is in
// force: a cleared or lapsed limit leaves it.
func TestAdaptiveLimitsListWhatIsInForce(t *testing.T) {
	rec := newLimitRecorder()
	h, now := newLeasedHolder(rec)
	_ = h.SetAdaptiveRateLimitFor("198.51.100.7", time.Second, "WAF")
	*now = now.Add(time.Minute)
	_ = h.SetAdaptiveRateLimitFor("2001:db8:1:2::9", 200*time.Millisecond, "RL")
	*now = now.Add(time.Minute)
	_ = h.SetAdaptiveRateLimit("198.51.100.8", 10*time.Millisecond)

	got := h.AdaptiveLimits()
	want := []AdaptiveLimit{
		{Key: "198.51.100.8", Interval: 10 * time.Millisecond, SetAt: *now, Expires: now.Add(AdaptiveLimitLease)},
		{Key: "2001:db8:1:2::", Interval: 200 * time.Millisecond, Reason: "RL",
			SetAt: now.Add(-time.Minute), Expires: now.Add(AdaptiveLimitLease - time.Minute)},
		{Key: "198.51.100.7", Interval: time.Second, Reason: "WAF",
			SetAt: now.Add(-2 * time.Minute), Expires: now.Add(AdaptiveLimitLease - 2*time.Minute)},
	}
	if !slices.Equal(got, want) || h.AdaptiveLimitCount() != 3 {
		t.Fatalf("listed %+v (count %d), want %+v", got, h.AdaptiveLimitCount(), want)
	}

	_ = h.ClearAdaptiveRateLimit("2001:db8:1:2::1")
	h.expireAdaptiveLimits(now.Add(AdaptiveLimitLease - 2*time.Minute))
	if got := h.AdaptiveLimits(); len(got) != 1 || got[0].Key != "198.51.100.8" {
		t.Errorf("after one clear and one lapse the table lists %+v, want only 198.51.100.8", got)
	}
}

// TestALimitsReasonIsBounded: the table can hold twenty thousand entries.
func TestALimitsReasonIsBounded(t *testing.T) {
	h, _ := newLeasedHolder(newLimitRecorder())
	_ = h.SetAdaptiveRateLimitFor("198.51.100.9", time.Second, strings.Repeat("r", 10*maxLimitReasonBytes))
	if got := h.AdaptiveLimits(); len(got[0].Reason) != maxLimitReasonBytes {
		t.Errorf("a %d-byte reason was kept at %d bytes", 10*maxLimitReasonBytes, len(got[0].Reason))
	}
}

// TestSetAdaptiveRateLimitForFallsBackOnAPlainManager: a writer holding some
// other Manager still sets its limit.
func TestSetAdaptiveRateLimitForFallsBackOnAPlainManager(t *testing.T) {
	rec := newLimitRecorder()
	if err := SetAdaptiveRateLimitFor(rec, "198.51.100.10", time.Second, "why"); err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.limits["198.51.100.10"]; !ok {
		t.Errorf("the limit was not set on a manager that keeps no reasons")
	}
}
