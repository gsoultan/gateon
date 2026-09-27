// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import "testing"

// TestHolderKeepsTheRLFeedbackHandlerAcrossSwaps: the server installs the
// reinforcement-learning feedback handler once, at startup, and the security
// supervisor replaces the eBPF manager whenever an eBPF setting changes. The
// handler lived only on the manager present at startup, so the first eBPF
// settings change -- or turning eBPF on after boot -- left neural-sentinel
// feedback going nowhere until the process restarted.
func TestHolderKeepsTheRLFeedbackHandlerAcrossSwaps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		atStartup Manager
	}{
		{"on at startup, then reconfigured", NewEbpfManager(nil)},
		{"off at startup, then turned on", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHolder(tc.atStartup)
			var got []string
			h.SetRLFeedbackHandler(func(ip string, _ float64) { got = append(got, ip) })

			// What reconcileEbpf does: tear the running manager down, then
			// install a freshly built one.
			h.Swap(nil)
			h.Swap(NewEbpfManager(nil))

			if err := h.ApplyRLFeedback("192.0.2.7", 0.9); err != nil {
				t.Fatalf("ApplyRLFeedback: %v", err)
			}
			if len(got) != 1 || got[0] != "192.0.2.7" {
				t.Fatalf("feedback reaching the handler after the manager was replaced = %v, want [192.0.2.7]", got)
			}
		})
	}
}

// interleavingManager runs hook the first time it is handed a feedback
// handler, which lets a test land a SetRLFeedbackHandler inside Swap's window
// between handing a manager the current handler and publishing it.
type interleavingManager struct {
	*EbpfManager
	hook func()
}

func (m *interleavingManager) SetRLFeedbackHandler(f func(ip string, score float64)) {
	m.EbpfManager.SetRLFeedbackHandler(f)
	if hook := m.hook; hook != nil {
		m.hook = nil
		hook()
	}
}

// TestHolderSwapPicksUpAHandlerInstalledMidSwap: a handler installed while a
// manager is being swapped in must end up on that manager, not the one it
// replaced.
func TestHolderSwapPicksUpAHandlerInstalledMidSwap(t *testing.T) {
	h := NewHolder(nil)
	h.SetRLFeedbackHandler(func(string, float64) { t.Error("feedback reached the superseded handler") })

	var got []string
	m := &interleavingManager{EbpfManager: NewEbpfManager(nil)}
	m.hook = func() {
		h.SetRLFeedbackHandler(func(ip string, _ float64) { got = append(got, ip) })
	}
	h.Swap(m)

	if err := h.ApplyRLFeedback("192.0.2.8", 0.5); err != nil {
		t.Fatalf("ApplyRLFeedback: %v", err)
	}
	if len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("feedback reaching the handler installed mid-swap = %v, want [192.0.2.8]", got)
	}
}
