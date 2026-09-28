// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Kernel rate limits appeared nowhere an operator looks. Five components set
// them and the mitigation page listed none, so an address could be held to a
// few packets a second with nothing to show it or release it from. Found by
// the 2026-09-27 AI-analysis review as an open finding (the throttle list);
// fixed with the move to the RL limiter.

// TestAutomaticThrottleIsVisibleToTheOperator: an address the RL limiter
// throttled is on the IP mitigation list the dashboard reads -- with its rate,
// its reason and when it lapses -- and counted in the mitigation total, and the
// dashboard's Allow on that row takes it off the list.
//
// The open version of this test looked in the ip_mitigations table. A throttle
// is not a block and is not stored; the dashboard's list is ListSecurityThreats,
// so that is where it is asked for.
func TestAutomaticThrottleIsVisibleToTheOperator(t *testing.T) {
	const ip = "10.60.0.3"
	s, rec := throttleTestService(t)
	runPasses(s, 3, neuralFinding(ip, 95))
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("precondition: the findings did not throttle %s", ip)
	}

	row := listedThrottle(t, s, "ipMitigated", ip)
	if row == nil {
		t.Fatalf("%s is throttled in the kernel and appears nowhere on the IP mitigation list", ip)
	}
	limits := holderOf(t, s).AdaptiveLimits()
	expiry := limits[0].Expires.UTC().Format(time.RFC3339)
	for _, want := range []string{"100 packets a second", "Neural Sentinel", "Lapses at " + expiry} {
		if !strings.Contains(row.GetDescription(), want) {
			t.Errorf("the listing does not say %q: %q", want, row.GetDescription())
		}
	}
	if !row.GetMitigated() || row.GetActionTaken() != telemetry.ActionThrottled {
		t.Errorf("listed as mitigated=%v, action %q", row.GetMitigated(), row.GetActionTaken())
	}
	if listedThrottle(t, s, "mitigated", ip) == nil || listedThrottle(t, s, "userMitigated", ip) != nil {
		t.Errorf("a throttle belongs on the combined and IP lists and not on the user list")
	}
	diag, err := s.GetDiagnostics(t.Context(), &gateonv1.GetDiagnosticsRequest{})
	if err != nil || diag.GetTotalMitigations() != 1 {
		t.Errorf("the mitigation total is %d (err %v), want the one throttle", diag.GetTotalMitigations(), err)
	}

	if _, err := s.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: row.GetSource()}); err != nil {
		t.Fatal(err)
	}
	if listedThrottle(t, s, "ipMitigated", ip) != nil || rec.throttled([]string{ip}) != 0 {
		t.Errorf("Allow on the listed throttle left it in place")
	}
}

// TestMitigationListPagesThroughThrottlesThenStoredMitigations: throttles come
// first and the stored mitigations carry on after them, one page at a time,
// with every page counting both.
func TestMitigationListPagesThroughThrottlesThenStoredMitigations(t *testing.T) {
	s, _ := throttleTestService(t)
	holder := holderOf(t, s)
	for _, ip := range []string{"10.61.0.1", "10.61.0.2"} {
		if err := holder.SetAdaptiveRateLimitFor(ip, time.Second, "test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"10.62.0.1", "10.62.0.2", "10.62.0.3"} {
		if err := telemetry.MarkIPMitigated(ip, "test"); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	for offset := 0; offset < 6; offset += 2 {
		resp, err := s.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{
			Status: "ipMitigated", Limit: 2, Offset: int32(offset),
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetTotalCount() != 5 {
			t.Errorf("offset %d: total %d, want 5", offset, resp.GetTotalCount())
		}
		for _, a := range resp.GetThreats() {
			seen = append(seen, a.GetType()+" "+a.GetSource())
		}
	}
	if len(seen) != 5 || !strings.HasPrefix(seen[0], kernelThrottleType) || !strings.HasPrefix(seen[1], kernelThrottleType) ||
		strings.HasPrefix(seen[2], kernelThrottleType) {
		t.Errorf("paged through %v; want the 2 throttles, then the 3 stored mitigations", seen)
	}
	slices.Sort(seen)
	if len(slices.Compact(seen)) != 5 {
		t.Errorf("a row was listed twice or lost between pages: %v", seen)
	}
}

// TestTheMitigationListTakesAnyPageItIsAskedFor: the page comes from the
// client. A negative offset slices below zero, and a limit is not a size to
// allocate up front.
func TestTheMitigationListTakesAnyPageItIsAskedFor(t *testing.T) {
	s, _ := throttleTestService(t)
	if err := holderOf(t, s).SetAdaptiveRateLimitFor("10.63.0.1", time.Second, "test"); err != nil {
		t.Fatal(err)
	}
	for _, page := range []struct{ limit, offset int32 }{{2, -5}, {1 << 30, 0}} {
		resp, err := s.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{
			Status: "ipMitigated", Limit: page.limit, Offset: page.offset,
		})
		if err != nil || len(resp.GetThreats()) != 1 {
			t.Errorf("limit %d, offset %d: %d rows (err %v), want the one throttle", page.limit, page.offset,
				len(resp.GetThreats()), err)
		}
	}
}

// TestAnIPv6ThrottleIsListedAndReleasedByItsSlash64: the kernel limits IPv6 by
// /64, so that is what is listed, and the row's own Source releases it.
func TestAnIPv6ThrottleIsListedAndReleasedByItsSlash64(t *testing.T) {
	s, rec := throttleTestService(t)
	if err := holderOf(t, s).SetAdaptiveRateLimitFor("fd00:7:8:9::5", 200*time.Millisecond, "test"); err != nil {
		t.Fatal(err)
	}
	row := listedThrottle(t, s, "ipMitigated", "fd00:7:8:9::")
	if row == nil || !strings.Contains(row.GetDescription(), "fd00:7:8:9::/64") ||
		!strings.Contains(row.GetDescription(), "5 packets a second") {
		t.Fatalf("the /64's throttle is not listed as the /64's: %v", row)
	}
	if _, err := s.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: row.GetSource()}); err != nil {
		t.Fatal(err)
	}
	if len(rec.limitedAddresses()) != 0 {
		t.Errorf("Allow on the /64's row left %v limited", rec.limitedAddresses())
	}
}

// TestAThrottleIsListedWithWhenItLifts: when a kernel throttle lapses was only
// in the row's description, as prose, so the dashboard could not count down to
// it. The row carries the lease's end as a field of its own, from the Holder's
// lease table, and a renewal moves it.
func TestAThrottleIsListedWithWhenItLifts(t *testing.T) {
	s, _ := throttleTestService(t)
	holder := holderOf(t, s)
	if err := holder.SetAdaptiveRateLimitFor("10.64.0.1", time.Second, "test"); err != nil {
		t.Fatal(err)
	}
	row := listedThrottle(t, s, "ipMitigated", "10.64.0.1")
	if row == nil {
		t.Fatal("the throttle is not listed")
	}
	lease := holder.AdaptiveLimits()[0]
	want := lease.Expires.UTC().Format(time.RFC3339)
	if row.GetExpiresAt() != want {
		t.Fatalf("expires_at = %q, want the lease's end %q", row.GetExpiresAt(), want)
	}
	at, err := time.Parse(time.RFC3339, row.GetExpiresAt())
	if err != nil {
		t.Fatalf("expires_at %q is not RFC 3339: %v", row.GetExpiresAt(), err)
	}
	if d := at.Sub(lease.SetAt); d < ebpf.AdaptiveLimitLease-time.Second || d > ebpf.AdaptiveLimitLease {
		t.Errorf("expires_at is %s after the limit was set, want the %s lease", d, ebpf.AdaptiveLimitLease)
	}

	// A stored mitigation carries no lease; the field stays empty rather than
	// naming a moment nothing will act on.
	if err := telemetry.MarkIPMitigated("10.64.0.2", "test"); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{Status: "ipMitigated", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range resp.GetThreats() {
		if a.GetSource() == "10.64.0.2" && a.GetExpiresAt() != "" {
			t.Errorf("a stored IP block, which has no expiry, is listed as lifting at %q", a.GetExpiresAt())
		}
	}
}

// TestTheExpiryOfNothingIsEmpty: a zero time formats as year one, which a
// countdown would show as a limit that lifted two thousand years ago.
func TestTheExpiryOfNothingIsEmpty(t *testing.T) {
	if got := rfc3339OrEmpty(time.Time{}); got != "" {
		t.Errorf("rfc3339OrEmpty(zero) = %q, want empty", got)
	}
	at := time.Date(2026, 9, 27, 23, 5, 0, 0, time.FixedZone("x", 7*3600))
	if got := rfc3339OrEmpty(at); got != "2026-09-27T16:05:00Z" {
		t.Errorf("rfc3339OrEmpty = %q, want it in UTC", got)
	}
}

// listedThrottle is the kernel_throttle row for source on the mitigation list
// status names, or nil.
func listedThrottle(t *testing.T, s *ApiService, status, source string) *gateonv1.Anomaly {
	t.Helper()
	resp, err := s.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{Status: status, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range resp.GetThreats() {
		if a.GetType() == kernelThrottleType && a.GetSource() == source {
			return a
		}
	}
	return nil
}

// holderOf is the eBPF holder a throttleTestService limits through.
func holderOf(t *testing.T, s *ApiService) *ebpf.Holder {
	t.Helper()
	h, ok := s.EbpfManager.(*ebpf.Holder)
	if !ok {
		t.Fatalf("the service does not limit through an ebpf.Holder")
	}
	return h
}
