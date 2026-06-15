package ebpf

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubManager is a minimal Manager that records the calls it receives and lets
// a test inject an error so delegation can be asserted.
type stubManager struct {
	started   bool
	lastShun  string
	err       error
	mapStats  MapStats
	callCount int
}

func (s *stubManager) Start(context.Context)                     { s.started = true }
func (s *stubManager) ShunIP(ip string) error                    { s.callCount++; s.lastShun = ip; return s.err }
func (s *stubManager) UnshunIP(string) error                     { s.callCount++; return s.err }
func (s *stubManager) BlockCountry(string) error                 { s.callCount++; return s.err }
func (s *stubManager) UpdateManagementWhitelist([]string) error  { s.callCount++; return s.err }
func (s *stubManager) SetPortKnockingSequence([]int32) error     { s.callCount++; return s.err }
func (s *stubManager) UpdateLoadBalancerBackends([]string) error { s.callCount++; return s.err }
func (s *stubManager) SetAdaptiveRateLimit(string, time.Duration) error {
	s.callCount++
	return s.err
}
func (s *stubManager) ShunJA3([16]byte) error         { s.callCount++; return s.err }
func (s *stubManager) UnshunJA3([16]byte) error       { s.callCount++; return s.err }
func (s *stubManager) ShunJA4(string) error           { s.callCount++; return s.err }
func (s *stubManager) BlocklistCuckoo(string) error   { s.callCount++; return s.err }
func (s *stubManager) GetMapStats() (MapStats, error) { s.callCount++; return s.mapStats, s.err }

// TestHolderNoOpWhenEmpty verifies that every mutating call is a safe no-op and
// GetMapStats returns empty stats when no underlying manager is installed.
func TestHolderNoOpWhenEmpty(t *testing.T) {
	h := NewHolder(nil)

	if h.Current() != nil {
		t.Fatal("Current() must be nil for an empty holder")
	}

	calls := []struct {
		name string
		fn   func() error
	}{
		{"ShunIP", func() error { return h.ShunIP("1.2.3.4") }},
		{"UnshunIP", func() error { return h.UnshunIP("1.2.3.4") }},
		{"BlockCountry", func() error { return h.BlockCountry("US") }},
		{"UpdateManagementWhitelist", func() error { return h.UpdateManagementWhitelist(nil) }},
		{"SetPortKnockingSequence", func() error { return h.SetPortKnockingSequence(nil) }},
		{"UpdateLoadBalancerBackends", func() error { return h.UpdateLoadBalancerBackends(nil) }},
		{"SetAdaptiveRateLimit", func() error { return h.SetAdaptiveRateLimit("1.2.3.4", time.Second) }},
		{"ShunJA3", func() error { return h.ShunJA3([16]byte{}) }},
		{"UnshunJA3", func() error { return h.UnshunJA3([16]byte{}) }},
		{"ShunJA4", func() error { return h.ShunJA4("ja4") }},
		{"BlocklistCuckoo", func() error { return h.BlocklistCuckoo("1.2.3.4") }},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err != nil {
				t.Fatalf("%s on empty holder = %v; want nil", tc.name, err)
			}
		})
	}

	// Start must not panic on an empty holder.
	h.Start(t.Context())

	stats, err := h.GetMapStats()
	if err != nil {
		t.Fatalf("GetMapStats on empty holder = %v; want nil", err)
	}
	if stats.ShunnedIPsCount != 0 || len(stats.DroppedPackets) != 0 {
		t.Fatalf("GetMapStats on empty holder = %+v; want zero value", stats)
	}
}

// TestHolderDelegates verifies that calls are forwarded to the installed
// manager and that its return values (including errors) propagate.
func TestHolderDelegates(t *testing.T) {
	wantErr := errors.New("boom")
	stub := &stubManager{
		err:      wantErr,
		mapStats: MapStats{ShunnedIPsCount: 7},
	}
	h := NewHolder(stub)

	if h.Current() != stub {
		t.Fatal("Current() must return the installed manager")
	}

	if err := h.ShunIP("9.9.9.9"); !errors.Is(err, wantErr) {
		t.Fatalf("ShunIP error = %v; want %v", err, wantErr)
	}
	if stub.lastShun != "9.9.9.9" {
		t.Fatalf("delegated ShunIP arg = %q; want 9.9.9.9", stub.lastShun)
	}

	h.Start(t.Context())
	if !stub.started {
		t.Fatal("Start was not delegated to the underlying manager")
	}

	stats, err := h.GetMapStats()
	if !errors.Is(err, wantErr) {
		t.Fatalf("GetMapStats error = %v; want %v", err, wantErr)
	}
	if stats.ShunnedIPsCount != 7 {
		t.Fatalf("GetMapStats = %+v; want ShunnedIPsCount=7", stats)
	}
}

// TestHolderSwap verifies that swapping the underlying manager (including back
// to nil) routes subsequent calls to the new target.
func TestHolderSwap(t *testing.T) {
	first := &stubManager{}
	second := &stubManager{}
	h := NewHolder(first)

	_ = h.ShunIP("a")
	if first.callCount != 1 || second.callCount != 0 {
		t.Fatalf("after first call: first=%d second=%d; want 1 and 0", first.callCount, second.callCount)
	}

	h.Swap(second)
	_ = h.ShunIP("b")
	if first.callCount != 1 || second.callCount != 1 {
		t.Fatalf("after swap+call: first=%d second=%d; want 1 and 1", first.callCount, second.callCount)
	}

	h.Swap(nil)
	if h.Current() != nil {
		t.Fatal("Swap(nil) must clear the underlying manager")
	}
	if err := h.ShunIP("c"); err != nil {
		t.Fatalf("ShunIP after Swap(nil) = %v; want nil (no-op)", err)
	}
	if first.callCount != 1 || second.callCount != 1 {
		t.Fatalf("after Swap(nil)+call: first=%d second=%d; want unchanged 1 and 1", first.callCount, second.callCount)
	}
}
