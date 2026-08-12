// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
)

// recordingEbpf records adaptive limit calls so tests can assert on what
// actually reached the kernel-facing interface.
type recordingEbpf struct {
	ebpf.Manager

	mu      sync.Mutex
	set     map[string]time.Duration
	cleared map[string]int
}

func newRecordingEbpf() *recordingEbpf {
	return &recordingEbpf{set: map[string]time.Duration{}, cleared: map[string]int{}}
}

func (r *recordingEbpf) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.set[ip] = interval
	return nil
}

func (r *recordingEbpf) ClearAdaptiveRateLimit(ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleared[ip]++
	delete(r.set, ip)
	return nil
}

func (r *recordingEbpf) limitFor(ip string) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.set[ip]
	return d, ok
}

func (r *recordingEbpf) clearCount(ip string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleared[ip]
}

// TestThrottledIPCanBeReleased is the regression test for the permanent
// throttle.
//
// Root cause: applyAdaptiveLimit computed interval = 0 for a decayed threat
// score and then skipped the eBPF call behind `if interval > 0`, and the
// Manager interface had no clear operation at all. A limit could be installed
// but never removed, so any false positive — a NAT gateway, a CI runner, a
// corporate egress IP — was throttled to one packet per 10ms for the life of
// the process with no path back.
func TestThrottledIPCanBeReleased(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)

	const ip = "203.0.113.7"

	// Drive the score up until a limit is installed.
	for range 30 {
		rl.ProcessFeedback(ip, 1.0)
	}
	if _, ok := mgr.limitFor(ip); !ok {
		t.Fatal("sustained max-threat feedback did not install any limit")
	}

	// The IP goes quiet: no further feedback, only time passing.
	base := time.Now()
	rl.now = func() time.Time { return base.Add(2 * time.Hour) }

	// One benign observation after the quiet period must release it.
	rl.ProcessFeedback(ip, 0.0)

	if d, ok := mgr.limitFor(ip); ok {
		t.Fatalf("a decayed IP is still throttled at %v — a false positive can never recover", d)
	}
	if mgr.clearCount(ip) == 0 {
		t.Error("no clear was issued; the limit was abandoned rather than released")
	}
}

// TestStateMapIsBounded covers the unbounded-map defect. The keys are remote
// addresses chosen by whoever is sending traffic, so without a ceiling a single
// host walking an IPv6 /64 grows this map without limit.
func TestStateMapIsBounded(t *testing.T) {
	rl := NewReinforcementLearningLimiter(nil)
	capacity := config.CurrentTierDefaults().RLLimiterStates
	if capacity <= 0 {
		t.Fatal("tier defaults must supply a positive RL limiter capacity")
	}

	for i := range capacity * 2 {
		rl.ProcessFeedback(fmt.Sprintf("2001:db8::%x", i), 0.95)
	}

	if got := rl.Len(); got > capacity {
		t.Errorf("state map grew to %d entries, past its %d ceiling", got, capacity)
	}
	if rl.Len() == 0 {
		t.Error("state map is empty; the limiter is not tracking anything")
	}
}

// TestConcurrentFeedbackDoesNotLoseUpdates covers the Load-then-Store race.
// Two goroutines reporting the same IP each built their own IPState and locked
// their own mutex, so one update was silently dropped — invisible to the race
// detector precisely because the locks were different objects.
func TestConcurrentFeedbackDoesNotLoseUpdates(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)

	const ip = "198.51.100.4"
	const goroutines = 16
	const perGoroutine = 40

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				rl.ProcessFeedback(ip, 1.0)
			}
		}()
	}
	wg.Wait()

	if got := rl.Len(); got != 1 {
		t.Errorf("one IP produced %d state entries; concurrent creates were not deduplicated", got)
	}

	// 640 consecutive max-threat observations must land in the critical band.
	// If updates were being lost against separate states, the surviving state
	// would carry far fewer of them.
	d, ok := mgr.limitFor(ip)
	if !ok {
		t.Fatal("no limit installed after sustained concurrent max-threat feedback")
	}
	if d != 10*time.Millisecond {
		t.Errorf("want the critical-band interval (10ms) after %d max-threat observations, got %v — "+
			"updates were lost", goroutines*perGoroutine, d)
	}
}

// TestSweepReleasesIdleStates checks that the periodic sweep both frees Go
// memory and hands back the kernel map slot, which is a fixed resource.
func TestSweepReleasesIdleStates(t *testing.T) {
	mgr := newRecordingEbpf()
	rl := NewReinforcementLearningLimiter(mgr)

	const ip = "192.0.2.99"
	for range 30 {
		rl.ProcessFeedback(ip, 1.0)
	}
	if _, ok := mgr.limitFor(ip); !ok {
		t.Fatal("expected a limit to be installed")
	}

	base := time.Now()
	rl.now = func() time.Time { return base.Add(idleStateTTL + time.Minute) }
	rl.Sweep()

	if rl.Len() != 0 {
		t.Errorf("sweep left %d idle states behind", rl.Len())
	}
	if _, ok := mgr.limitFor(ip); ok {
		t.Error("sweep dropped the state but stranded the kernel limit with no owner to clear it")
	}
}

func TestDecayQValue(t *testing.T) {
	if got := decayQValue(1.0, 0); got != 1.0 {
		t.Errorf("no elapsed time must not decay: got %v", got)
	}
	oneHalfLife := decayQValue(1.0, qValueDecayHalfLife)
	if oneHalfLife > 0.55 || oneHalfLife < 0.45 {
		t.Errorf("one half-life should roughly halve the score, got %v", oneHalfLife)
	}
	if got := decayQValue(1.0, 100*qValueDecayHalfLife); got != 0 {
		t.Errorf("a long quiet period must decay to zero, got %v", got)
	}
	if got := decayQValue(0, time.Hour); got != 0 {
		t.Errorf("zero stays zero, got %v", got)
	}
}
