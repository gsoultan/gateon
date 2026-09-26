// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import "testing"

// TestRecommendedIndexIsTheInterfaceEBPFWouldUse: the picker used to recommend
// the first up, non-loopback interface with an IPv4 address. On a host whose
// default route is on a later interface that named one NIC while the gateway,
// left unconfigured, attached to another.
func TestRecommendedIndexIsTheInterfaceEBPFWouldUse(t *testing.T) {
	infos := []netInterfaceInfo{{Name: "lo"}, {Name: "docker0"}, {Name: "ens5"}}
	const firstUpWithIPv4 = 1 // docker0

	if got := recommendedIndex(infos, "ens5", firstUpWithIPv4); got != 2 {
		t.Errorf("default-route interface listed third: got index %d, want 2 (ens5)", got)
	}
	if got := recommendedIndex(infos, "ens9", firstUpWithIPv4); got != firstUpWithIPv4 {
		t.Errorf("default-route interface not listed: got index %d, want the fallback %d", got, firstUpWithIPv4)
	}
	if got := recommendedIndex(infos, "", firstUpWithIPv4); got != firstUpWithIPv4 {
		t.Errorf("no default-route interface: got index %d, want the fallback %d", got, firstUpWithIPv4)
	}
	if got := recommendedIndex(infos, "", -1); got != -1 {
		t.Errorf("nothing to recommend: got index %d, want -1", got)
	}
}
