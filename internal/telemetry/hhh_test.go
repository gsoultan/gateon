// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
)

func TestHHHCounter(t *testing.T) {
	c := NewHHHCounter()

	// Add some IPs
	c.Add("1.2.3.4")
	c.Add("1.2.3.5")
	c.Add("1.2.3.6")
	c.Add("1.2.4.1")

	// Total 4 requests.
	// 1.2.3.0/24 has 3 requests.
	// 1.2.4.1/32 has 1 request.
	// 1.2.0.0/16 has 4 requests.

	// Threshold 3 should catch 1.2.3.0/24 (count 3)
	// and NOT 1.2.0.0/16 because 1.2.0.0/16 conditioned frequency would be 4 - 3 = 1.
	hitters := c.GetHeavyHitters(3)
	found24 := false
	for _, h := range hitters {
		if h.Network == "1.2.3.0/24" {
			found24 = true
			if h.Count != 3 {
				t.Errorf("Expected count 3 for 1.2.3.0/24, got %d", h.Count)
			}
		}
		if h.Network == "1.2.0.0/16" {
			t.Errorf("1.2.0.0/16 should NOT be a heavy hitter at threshold 3 after subtraction")
		}
	}
	if !found24 {
		t.Errorf("Expected 1.2.3.0/24 to be a heavy hitter, got %v", hitters)
	}

	// Threshold 4 should catch 1.2.0.0/16 (count 4)
	// because it doesn't have any descendant HH that takes away its frequency.
	// Wait, if we check level 24 first, 1.2.3.0/24 has count 3, which is < 4.
	// So 1.2.3.0/24 is NOT HH.
	// 1.2.0.0/16 has count 4, so it IS HH.
	hitters = c.GetHeavyHitters(4)
	found16 := false
	for _, h := range hitters {
		if h.Network == "1.2.0.0/16" {
			found16 = true
			if h.Count != 4 {
				t.Errorf("Expected count 4 for 1.2.0.0/16, got %d", h.Count)
			}
		}
	}
	if !found16 {
		t.Errorf("Expected 1.2.0.0/16 to be a heavy hitter, got %v", hitters)
	}
}

func TestHHHCounterIPv6(t *testing.T) {
	c := NewHHHCounter()
	c.Add("2001:db8::1")
	c.Add("2001:db8::2")
	c.Add("2001:db8:1::1")

	// Threshold 2 should catch 2001:db8::/64
	hitters := c.GetHeavyHitters(2)
	found64 := false
	for _, h := range hitters {
		if h.Network == "2001:db8::/64" {
			found64 = true
		}
	}
	if !found64 {
		t.Errorf("Expected 2001:db8::/64 to be a heavy hitter, got %v", hitters)
	}
}

// The heavy-hitter walk was extracted into hittersAtLevels, subtractFromParents
// and nextLevelUp. The existing test above covers the IPv4 conditioning, which
// is the behaviour that matters; these cover the pieces that moved and the
// address family the original test never reached.

func TestNextLevelUp(t *testing.T) {
	v4 := []int{32, 24, 16, 8}
	tests := []struct {
		name string
		bits int
		want int
	}{
		{name: "from /32 to /24", bits: 32, want: 24},
		{name: "from /24 to /16", bits: 24, want: 16},
		{name: "from /16 to /8", bits: 16, want: 8},
		{name: "from /8 there is nowhere left to go", bits: 8, want: -1},
		{name: "below the least specific level", bits: 4, want: -1},
		{name: "between levels picks the next shorter", bits: 20, want: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextLevelUp(v4, tt.bits); got != tt.want {
				t.Errorf("nextLevelUp(%v, %d) = %d, want %d", v4, tt.bits, got, tt.want)
			}
		})
	}
}

// A /32 that clears the threshold must discount its /24 and /16 ancestors, not
// just its immediate parent — the walk continues to the root.
func TestSubtractFromParentsWalksTheWholeChain(t *testing.T) {
	c := NewHHHCounter()
	for range 5 {
		c.Add("10.1.2.3")
	}
	c.Add("10.1.2.9")
	c.Add("10.1.9.9")

	// At threshold 5 only the /32 qualifies; every ancestor should have had
	// those 5 removed, leaving them under the threshold.
	for _, h := range c.GetHeavyHitters(5) {
		if h.Network != "10.1.2.3/32" {
			t.Errorf("only the /32 should clear threshold 5, also got %s (count %d)",
				h.Network, h.Count)
		}
	}
}

func TestHeavyHittersIPv6(t *testing.T) {
	c := NewHHHCounter()
	for range 4 {
		c.Add("2001:db8:1:2::1")
	}
	c.Add("2001:db8:9:9::1")

	hitters := c.GetHeavyHitters(4)
	if len(hitters) == 0 {
		t.Fatal("expected an IPv6 heavy hitter at threshold 4, got none")
	}
	found := false
	for _, h := range hitters {
		if h.Network == "2001:db8:1:2::1/128" {
			found = true
			if h.Count != 4 {
				t.Errorf("count = %d, want 4", h.Count)
			}
			if h.Percentage <= 0 || h.Percentage > 100 {
				t.Errorf("percentage = %v, want a sane share of total", h.Percentage)
			}
		}
	}
	if !found {
		t.Errorf("expected the /128 to be reported, got %v", hitters)
	}
}

// v4 and v6 share one conditioned-frequency map across the two passes; neither
// family may consume the other's counts.
func TestHeavyHittersMixedFamiliesDoNotInterfere(t *testing.T) {
	c := NewHHHCounter()
	for range 3 {
		c.Add("192.168.5.5")
	}
	for range 3 {
		c.Add("2001:db8::5")
	}

	var sawV4, sawV6 bool
	for _, h := range c.GetHeavyHitters(3) {
		switch h.Network {
		case "192.168.5.5/32":
			sawV4 = true
		case "2001:db8::5/128":
			sawV6 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Errorf("expected both families reported; v4=%v v6=%v", sawV4, sawV6)
	}
}
