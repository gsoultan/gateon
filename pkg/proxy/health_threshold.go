// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import "sync"

// Default thresholds. Both are 2 rather than 1, which is a deliberate change
// from taking every single check result at face value.
//
// At 1, one failed check removes a backend. That sounds like fast detection and
// is mostly a way to lose a healthy pool: the checks for every target run in one
// loop on one goroutine, so whatever makes one check fail -- a GC pause, a
// scheduling delay, a moment of load on the gateway itself -- tends to fail all
// of them in the same tick. When that happens the pool empties, and an empty
// pool serves nothing. A whole service can go dark because the gateway was busy.
//
// The cost is real and worth stating plainly: a genuinely dead backend now keeps
// receiving traffic for two intervals instead of one. Both values are
// configurable per service for operators who would rather have the faster
// detection back.
const (
	defaultUnhealthyThreshold = 2
	defaultHealthyThreshold   = 2
)

// healthThresholds turns a stream of per-target check results into the far
// smaller stream of state changes that are worth acting on.
//
// It is deliberately not the load balancer's problem. The balancer answers
// "which target now", which is on the request path; deciding whether three
// failures in a row mean something belongs to the checker, which runs every
// fifteen seconds on its own goroutine.
type healthThresholds struct {
	unhealthy int32
	healthy   int32

	mu    sync.Mutex
	state map[string]*targetHealthState
}

type targetHealthState struct {
	// consecutive counts results of the current kind, reset by the other kind.
	consecutive int32
	// alive is what the balancer was last told, so a repeat is not re-sent.
	alive bool
	// seen distinguishes "no checks yet" from "checked and alive", so the very
	// first result does not have to clear a threshold to take effect.
	seen bool
}

func newHealthThresholds(unhealthy, healthy int32) *healthThresholds {
	if unhealthy <= 0 {
		unhealthy = defaultUnhealthyThreshold
	}
	if healthy <= 0 {
		healthy = defaultHealthyThreshold
	}
	return &healthThresholds{
		unhealthy: unhealthy,
		healthy:   healthy,
		state:     make(map[string]*targetHealthState),
	}
}

// record folds one check result into a target's history and reports whether the
// balancer should be told something new.
//
// The first result for a target is applied immediately whatever it says. A
// gateway that has just started knows nothing about its backends, and making a
// newly discovered target wait two intervals before it can be used -- or two
// intervals before an already-dead one stops being used -- would be treating an
// absence of history as evidence.
func (h *healthThresholds) record(target string, ok bool) (alive bool, changed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	s := h.state[target]
	if s == nil {
		s = &targetHealthState{}
		h.state[target] = s
	}

	if !s.seen {
		s.seen = true
		s.alive = ok
		// Zero, not one: consecutive counts results that *disagree* with the
		// current state, and this result established that state rather than
		// arguing with it.
		s.consecutive = 0
		return s.alive, true
	}

	// A result agreeing with the current state resets the opposing streak;
	// there is nothing to report.
	if ok == s.alive {
		s.consecutive = 0
		return s.alive, false
	}

	s.consecutive++
	need := h.unhealthy
	if ok {
		need = h.healthy
	}
	if s.consecutive < need {
		return s.alive, false
	}

	s.alive = ok
	s.consecutive = 0
	return s.alive, true
}

// forget drops a target's history.
//
// Called when discovery retires a target, so the map cannot grow without bound
// across a long-lived process whose backends come and go. A target that returns
// starts over with no history, which is the same position the gateway is in
// after a restart.
func (h *healthThresholds) forget(target string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.state, target)
}
