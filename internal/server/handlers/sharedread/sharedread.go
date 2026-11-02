// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package sharedread computes one result for every caller that asks inside a
// period. Every open /v1/diagnostics/watch stream computed its own snapshot on
// its own ticker: several database reads per stream per tick, with nothing
// shared between two operators on the same page. A Shared answers a caller
// whose tick finds a result younger than the period with that result, and
// callers that arrive while one is being computed wait for it rather than
// starting their own (ADR 0080).
package sharedread

import (
	"context"
	"sync"
	"time"
)

// Shared is one result computed at most once per period. It is safe for
// concurrent use; the result it hands out is shared and must only be read.
type Shared[T any] struct {
	period  time.Duration
	compute func(context.Context) (T, error)

	mu  sync.Mutex
	at  time.Time
	res T
	has bool
	// inflight is closed when the computation under way ends.
	inflight chan struct{}
}

// New returns a Shared that computes with compute and keeps the result for
// period. The computation runs under a context of its own, bounded by period:
// the caller that started it may leave before it ends, and the others
// waiting on it still want it.
func New[T any](period time.Duration, compute func(context.Context) (T, error)) *Shared[T] {
	return &Shared[T]{period: period, compute: compute}
}

// Get returns a result no older than the period, computing one when needed.
// It returns ctx's error if ctx ends while another caller's computation runs.
func (s *Shared[T]) Get(ctx context.Context) (T, error) {
	for {
		s.mu.Lock()
		if s.has && time.Since(s.at) < s.period {
			res := s.res
			s.mu.Unlock()
			return res, nil
		}
		if wait := s.inflight; wait != nil {
			s.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				var zero T
				return zero, ctx.Err()
			}
		}
		done := make(chan struct{})
		s.inflight = done
		s.mu.Unlock()

		// The computation outlives the caller that started it, since others may be
		// waiting on it, so it carries the caller's values but not its deadline.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.period)
		res, err := s.compute(cctx)
		cancel()

		s.mu.Lock()
		if err == nil {
			s.res, s.at, s.has = res, time.Now(), true
		}
		s.inflight = nil
		close(done)
		s.mu.Unlock()
		return res, err
	}
}
