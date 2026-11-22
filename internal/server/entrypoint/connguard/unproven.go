// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package connguard bounds what a connection may cost an HTTP entrypoint
// before it has done anything to earn it: connections that have not yet
// delivered a complete request (Unproven), and HTTP/2 connections whose client
// cancels streams faster than any browser does (Resets).
package connguard

import (
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Unproven tracks one entrypoint's connections that have not yet delivered a
// complete request: no TLS handshake finished, or no request's headers read.
//
// The 2026-11-13 review measured why it exists (D1). Such a connection held an
// entrypoint slot for the full ten-second header timeout, counted the same as
// one serving requests, and a full entrypoint refused the newcomer rather
// than the idlest holder. Sixty addresses reconnecting bare TCP connections,
// sending nothing, kept all 10,000 slots full and failed 183 of 189 requests
// from everyone else, at no TLS cost to themselves. Now each unproven
// connection has a short deadline of its own, a source address may hold only
// a few of them, and a full entrypoint closes the oldest to admit a new one.
//
// Unproven is safe for concurrent use. Its size is bounded by the
// entrypoint's connection limit: an entry exists only while its connection is
// open and unproven, and the per-address map only while an address has one.
type Unproven struct {
	mu         sync.Mutex
	head, tail *Entry // oldest first
	perAddr    map[netip.Addr]int
	limit      int // per address; > 0
	timeout    time.Duration
	pressured  time.Duration
}

// NewUnproven returns a tracker allowing perAddrLimit unproven connections per
// address, each closed after timeout, or after pressuredTimeout when it was
// admitted to an entrypoint under pressure. It returns nil, which admits
// everything and tracks nothing, when perAddrLimit is not positive.
func NewUnproven(perAddrLimit int, timeout, pressuredTimeout time.Duration) *Unproven {
	if perAddrLimit <= 0 {
		return nil
	}
	return &Unproven{
		perAddr:   make(map[netip.Addr]int),
		limit:     perAddrLimit,
		timeout:   timeout,
		pressured: pressuredTimeout,
	}
}

// Entry is one unproven connection. Its methods are safe to call more than
// once and from any goroutine; the first of Prove, Forget or an eviction or
// expiry wins and the rest do nothing.
type Entry struct {
	owner      *Unproven
	prev, next *Entry
	conn       io.Closer
	key        netip.Addr
	capped     bool
	timer      atomic.Pointer[time.Timer] // set after Admit returns; read by settle
	done       atomic.Bool
}

// Admit records conn, from key, as unproven. capped is false for an address
// exempt from per-address caps (loopback, the mitigation allowlist), which is
// tracked for eviction and the deadline but never counted against an
// address. pressure selects the shorter deadline. It reports false, admitting
// nothing, when key already holds its limit of unproven connections.
func (u *Unproven) Admit(conn io.Closer, key netip.Addr, capped, pressure bool) (*Entry, bool) {
	if u == nil {
		return nil, true
	}
	e := &Entry{owner: u, conn: conn, key: key, capped: capped}
	u.mu.Lock()
	if capped {
		if u.perAddr[key] >= u.limit {
			u.mu.Unlock()
			return nil, false
		}
		u.perAddr[key]++
	}
	u.pushLocked(e)
	u.mu.Unlock()

	d := u.timeout
	if pressure && u.pressured > 0 {
		d = u.pressured
	}
	if d > 0 {
		e.timer.Store(time.AfterFunc(d, e.expire))
	}
	return e, true
}

// Prove marks the connection as having delivered a complete request: its
// deadline is lifted and it stops counting as unproven. Cheap after the first
// call, which is what makes it safe to call on every request.
func (e *Entry) Prove() {
	if e == nil || e.done.Load() {
		return
	}
	e.settle()
}

// Proven reports whether the connection has left the unproven set, by proof,
// close, expiry or eviction.
func (e *Entry) Proven() bool { return e == nil || e.done.Load() }

// Forget is Prove for a connection that is closing.
func (e *Entry) Forget() { e.Prove() }

// expire closes a connection that is still unproven when its deadline passes.
func (e *Entry) expire() {
	if e.settle() {
		expiredTotal.Add(1)
		_ = e.conn.Close()
	}
}

// settle removes e from its tracker once, and reports whether this call did.
func (e *Entry) settle() bool {
	if !e.done.CompareAndSwap(false, true) {
		return false
	}
	if t := e.timer.Load(); t != nil {
		t.Stop()
	}
	u := e.owner
	u.mu.Lock()
	u.removeLocked(e)
	u.mu.Unlock()
	return true
}

// EvictOldest closes the longest-waiting unproven connection and reports
// whether there was one. The close runs outside the lock, and frees the
// connection's entrypoint slot before it returns.
func (u *Unproven) EvictOldest() bool {
	if u == nil {
		return false
	}
	for {
		u.mu.Lock()
		e := u.head
		u.mu.Unlock()
		if e == nil {
			return false
		}
		if e.settle() {
			evictedTotal.Add(1)
			_ = e.conn.Close()
			return true
		}
		// Proven or closed between the read and the settle; try the next.
	}
}

func (u *Unproven) pushLocked(e *Entry) {
	e.prev = u.tail
	if u.tail != nil {
		u.tail.next = e
	} else {
		u.head = e
	}
	u.tail = e
}

func (u *Unproven) removeLocked(e *Entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if u.head == e {
		u.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if u.tail == e {
		u.tail = e.prev
	}
	e.prev, e.next = nil, nil
	if !e.capped {
		return
	}
	if n := u.perAddr[e.key]; n <= 1 {
		delete(u.perAddr, e.key)
	} else {
		u.perAddr[e.key] = n - 1
	}
}

// Counters for metrics, read by the entrypoint package.
var expiredTotal, evictedTotal atomic.Uint64

// Expired is how many unproven connections were closed at their deadline.
func Expired() uint64 { return expiredTotal.Load() }

// Evicted is how many were closed to admit a newer connection.
func Evicted() uint64 { return evictedTotal.Load() }
