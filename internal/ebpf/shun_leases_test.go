// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"slices"
	"testing"
	"time"
)

// shunRecorder is a manager whose kernel shun map is a set.
type shunRecorder struct {
	stubManager
	shunned map[string]bool
	lifted  []string
}

func (r *shunRecorder) ShunIP(ip string) error {
	key, _ := leaseKey(ip)
	r.shunned[key] = true
	return nil
}

func (r *shunRecorder) UnshunIP(ip string) error {
	key, _ := leaseKey(ip)
	delete(r.shunned, key)
	r.lifted = append(r.lifted, ip)
	return nil
}

// An automatic shun lapses (ADR 0031), and the kernel's shun map has no
// expiry of its own: the sweep lifts a leased entry when its lease ends, and
// never one an operator put there, which holds until released.
func TestALapsedShunLeavesTheKernel(t *testing.T) {
	rec := &shunRecorder{shunned: map[string]bool{}}
	h := NewHolder(rec)
	at := time.Unix(1_700_000_000, 0)

	if err := h.ShunIPUntil("203.0.113.9", at.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := h.ShunIP("198.51.100.9"); err != nil { // an operator's block
		t.Fatal(err)
	}

	h.expireShuns(at.Add(15*time.Minute - time.Second))
	if !rec.shunned["203.0.113.9"] {
		t.Fatal("the sweep lifted a shun before its lease ended")
	}
	h.expireShuns(at.Add(15 * time.Minute))
	if rec.shunned["203.0.113.9"] {
		t.Error("a shun whose lease ended is still in the kernel's shun map: the address stays " +
			"dropped below a request path that has stopped refusing it")
	}
	h.expireShuns(at.Add(1000 * time.Hour))
	if !rec.shunned["198.51.100.9"] {
		t.Error("the sweep lifted an operator's block, which holds until released")
	}
	if n := h.ShunLeaseCount(); n != 1 {
		t.Errorf("%d shuns are leased after the sweep, want the operator's 1", n)
	}
}

// Two addresses in one IPv6 /64 share one kernel entry, so the entry holds
// for the later of their leases, and an operator's block on either holds it
// until released.
func TestASharedKernelEntryHoldsForItsLongestShun(t *testing.T) {
	rec := &shunRecorder{shunned: map[string]bool{}}
	h := NewHolder(rec)
	at := time.Unix(1_700_000_000, 0)
	_ = h.ShunIPUntil("2001:db8::1", at.Add(time.Hour))
	_ = h.ShunIPUntil("2001:db8::2", at.Add(15*time.Minute)) // same /64, shorter

	h.expireShuns(at.Add(30 * time.Minute))
	if len(rec.lifted) != 0 {
		t.Fatalf("the /64 was lifted at the shorter lease (%v) while the longer one holds", rec.lifted)
	}
	_ = h.ShunIP("2001:db8::3") // an operator's block in the same /64
	h.expireShuns(at.Add(2 * time.Hour))
	if len(rec.lifted) != 0 {
		t.Errorf("the /64 was lifted (%v) while an operator's block in it holds", rec.lifted)
	}

	// A release lifts it and forgets the lease, so nothing sweeps it again.
	_ = h.UnshunIP("2001:db8::3")
	if n := h.ShunLeaseCount(); n != 0 {
		t.Errorf("%d leases remain after the release", n)
	}
	if !slices.Contains(rec.lifted, "2001:db8::3") {
		t.Error("the release did not reach the kernel")
	}
}

// A swapped-in manager starts with empty maps, so there is nothing to lift.
func TestASwapForgetsTheShunLeases(t *testing.T) {
	h := NewHolder(&shunRecorder{shunned: map[string]bool{}})
	_ = h.ShunIPUntil("203.0.113.10", time.Now().Add(time.Hour))
	h.Swap(&shunRecorder{shunned: map[string]bool{}})
	if n := h.ShunLeaseCount(); n != 0 {
		t.Errorf("%d leases survived the swap", n)
	}
}
