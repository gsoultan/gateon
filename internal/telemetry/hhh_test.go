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
