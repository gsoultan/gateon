// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package lookupgate runs the request path's block lookups against the
// database so that a database that does not answer cannot hold a request, or
// a connection being accepted, for longer than a deadline (ADR 0054).
//
// Three properties, each one a way the lookups used to stall every client of
// a gateway whose Postgres had hung:
//
//   - A caller waits for a lookup no longer than the gate's deadline, or its
//     own context, whichever ends first -- whether or not the driver honours
//     the context. lib/pq does not: on a cancelled context it asks the server
//     to cancel the query and goes on waiting for the server's answer, which a
//     stopped server never sends. So the query runs on a goroutine of its own
//     and the caller stops waiting for it, rather than relying on the driver
//     to stop.
//   - Concurrent lookups of one key share one query.
//   - At most Slots' capacity lookups are in flight in total, across every
//     gate that shares them. A lookup that would exceed it is not queued: the
//     caller is answered ErrSaturated at once and decides without the
//     database. A query the driver cannot abandon keeps its slot until it
//     ends, so a hung database costs at most that many goroutines and pool
//     connections, never one per request.
package lookupgate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrTimeout is what a caller is answered when the lookup it waited for did
// not finish within the deadline, or the caller's own context ended first.
var ErrTimeout = errors.New("block lookup timed out")

// ErrSaturated is what a caller is answered when every slot is held by a
// lookup in flight: it was not started, and nothing waited.
var ErrSaturated = errors.New("too many block lookups in flight")

// Slots bounds how many lookups are in flight at once across the gates that
// share it.
type Slots struct {
	c chan struct{}
}

// NewSlots returns a bound of n lookups in flight; n below 1 is 1.
func NewSlots(n int) *Slots {
	return &Slots{c: make(chan struct{}, max(n, 1))}
}

// InFlight reports how many slots are held.
func (s *Slots) InFlight() int { return len(s.c) }

// Cap reports the bound.
func (s *Slots) Cap() int { return cap(s.c) }

func (s *Slots) tryAcquire() bool {
	select {
	case s.c <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Slots) release() { <-s.c }

// Read is one lookup: it answers for key, and is handed a context that ends at
// the gate's deadline. It runs on a goroutine of its own and may outlive every
// caller waiting for it; whatever it must keep (a cache entry) it keeps itself.
type Read[V any] func(ctx context.Context, key string) (V, error)

// call is one lookup in flight, and every caller waiting for it.
type call[V any] struct {
	// done is closed once val and err are set.
	done chan struct{}
	// ctx ends at the lookup's deadline: a caller stops waiting there even if
	// the query does not.
	ctx context.Context
	val V
	err error
}

// Gate collapses and bounds one kind of lookup. Its map holds an entry only
// while a lookup is in flight, and each entry holds a slot, so it never has
// more entries than Slots' capacity.
type Gate[V any] struct {
	slots   *Slots
	read    Read[V]
	timeout atomic.Int64
	mu      sync.Mutex
	calls   map[string]*call[V]
	wg      sync.WaitGroup
}

// New returns a gate running read under slots, each lookup bounded by
// timeout.
func New[V any](slots *Slots, timeout time.Duration, read Read[V]) *Gate[V] {
	g := &Gate[V]{slots: slots, read: read, calls: make(map[string]*call[V])}
	g.SetTimeout(timeout)
	return g
}

// SetTimeout changes the deadline of lookups started from now on. A value
// below a millisecond is a millisecond: no deadline at all is the defect this
// package exists to remove.
func (g *Gate[V]) SetTimeout(d time.Duration) {
	g.timeout.Store(int64(max(d, time.Millisecond)))
}

// Timeout reports the deadline lookups start with.
func (g *Gate[V]) Timeout() time.Duration { return time.Duration(g.timeout.Load()) }

// Do answers key: from the lookup already in flight for it, or from a new one.
// It returns within the deadline, or when ctx ends, whichever is first --
// ErrTimeout then -- and at once with ErrSaturated when no slot is free.
func (g *Gate[V]) Do(ctx context.Context, key string) (V, error) {
	var zero V
	if ctx.Err() != nil {
		// The caller has nothing left to wait with: start nothing for it.
		return zero, ErrTimeout
	}
	c := g.join(key)
	if c == nil {
		return zero, ErrSaturated
	}
	select {
	case <-c.done:
		return c.val, c.err
	case <-c.ctx.Done():
	case <-ctx.Done():
	}
	// The lookup may have finished at the very moment either deadline did.
	select {
	case <-c.done:
		return c.val, c.err
	default:
		return zero, ErrTimeout
	}
}

// Refresh starts a lookup of key that nobody waits for, unless one is already
// in flight or no slot is free; it reports whether one is running now.
func (g *Gate[V]) Refresh(key string) bool {
	return g.join(key) != nil
}

// Wait returns once every lookup started so far has ended.
func (g *Gate[V]) Wait() { g.wg.Wait() }

// join returns the lookup in flight for key, starting one if there is none
// and a slot is free; nil when there is none and no slot.
func (g *Gate[V]) join(key string) *call[V] {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.calls[key]; ok {
		return c
	}
	if !g.slots.tryAcquire() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.Timeout())
	c := &call[V]{done: make(chan struct{}), ctx: ctx}
	g.calls[key] = c
	g.wg.Go(func() { g.run(c, key, cancel) })
	return c
}

// run performs c's lookup, publishes its answer and frees its slot -- when
// the read returns, which for a driver that ignores its context is when the
// database answers.
func (g *Gate[V]) run(c *call[V], key string, cancel context.CancelFunc) {
	defer cancel()
	c.val, c.err = g.read(c.ctx, key)
	close(c.done)
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	g.slots.release()
}
