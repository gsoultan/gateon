// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"testing"
	"time"
)

// TestReleaseLiftsTheBanAndResetsTheLadder pins both halves of an operator's
// release: the address is no longer refused, and its next trap hit is treated
// as a first one. Keeping the strikes would put a released address straight
// back on the rung the mistake had reached -- a day's ban for one more hit.
func TestReleaseLiftsTheBanAndResetsTheLadder(t *testing.T) {
	resetHoneypotState(t)
	const ip = "203.0.113.178"
	now := time.Now()

	for range len(honeypotBanLadder) {
		blockHoneypotIP(ip, now.Add(honeypotBanFor(ip, now)))
	}
	if !honeypotBanActive(ip) {
		t.Fatal("setup: the address is not banned after reaching the top of the ladder")
	}

	if !ReleaseHoneypotBan(ip) {
		t.Error("the release reported there was no ban to lift")
	}
	if honeypotBanActive(ip) {
		t.Fatal("the address is still banned after its release")
	}
	if got := honeypotBanFor(ip, now); got != honeypotBanLadder[0] {
		t.Errorf("the first hit after a release was banned for %s, want %s: the "+
			"release kept the strikes that led up to it", got, honeypotBanLadder[0])
	}
	if ReleaseHoneypotBan("198.51.100.178") {
		t.Error("releasing an address that was never banned reported a ban lifted")
	}
}
