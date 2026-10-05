// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package blocklist holds the blocks in force that a node enforces without
// asking the database (ADR 0058): the address shuns and the fingerprint
// blocks, read in whole at start-up and again on a schedule, plus this node's
// own blocks and releases since the last read.
//
// The enforcement cache in front of the database (ADR 0043, 0054) learns a
// block only by looking it up, one key at a time, and a lookup that cannot
// run -- the gate saturated, the database slow or hung -- decides its request
// served. So a block this node had not looked up since it started was not
// enforced exactly when an attacker with many addresses made the lookups
// saturate. A list read in advance answers for every block on it with no
// lookup at all.
//
// Readers never lock: the list is an immutable view behind an atomic pointer,
// replaced whole by its writers -- the periodic read, and this node's own
// block and release writes -- which serialise on a mutex among themselves.
package blocklist

import (
	"maps"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// What a block's end means. A block lapses at a Unix-nanosecond end; Forever
// holds until released, and Released is a release this node wrote.
const (
	Released int64 = 0
	Forever  int64 = -1
)

// Bounds is how much the list holds.
type Bounds struct {
	// Entries bounds the blocks read from the database, per kind. A list
	// larger than it is read newest first, and the rest are left to the
	// lookups, as before the list existed.
	Entries int
	// KeyBytes bounds one fingerprint key. A longer one is left to the
	// lookups.
	KeyBytes int
	// Edits bounds this node's writes kept over the last read, per kind.
	Edits int
}

// List is the blocks in force a node enforces without a lookup.
type List struct {
	bounds Bounds
	cur    atomic.Pointer[view]
	mu     sync.Mutex // writers only
	seq    uint64     // under mu: counts writes
	// discardBefore is the oldest read a Replace may still apply: a release
	// that did not fit in the edits was applied to the base itself, and a
	// read begun before it may hold the block it released.
	discardBefore uint64
}

// view is one immutable state of the list.
type view struct {
	addrs     map[netip.Addr]int64
	keys      map[string]int64
	addrEdits map[netip.Addr]edit
	keyEdits  map[string]edit
	complete  [2]bool // addrs, keys: everything in force was read
}

// edit is one of this node's writes since a read began.
type edit struct {
	until int64
	seq   uint64
}

// New returns an empty list held to b.
func New(b Bounds) *List {
	l := &List{bounds: b}
	l.cur.Store(&view{})
	return l
}

// AddressBlocked reports whether the list holds a block in force for a,
// which is repid.Address's key.
func (l *List) AddressBlocked(a netip.Addr) bool {
	v := l.cur.Load()
	if e, ok := v.addrEdits[a]; ok {
		return active(e.until)
	}
	until, ok := v.addrs[a]
	return ok && active(until)
}

// KeyBlocked reports whether the list holds a block in force for a
// fingerprint key (repid.For).
func (l *List) KeyBlocked(key string) bool {
	v := l.cur.Load()
	if e, ok := v.keyEdits[key]; ok {
		return active(e.until)
	}
	until, ok := v.keys[key]
	return ok && active(until)
}

// HasAddresses and HasKeys report whether there is anything to ask, so a
// caller with a key to build first skips building it on an empty list.
func (l *List) HasAddresses() bool {
	v := l.cur.Load()
	return len(v.addrs) > 0 || len(v.addrEdits) > 0
}

// HasKeys is HasAddresses for fingerprint keys.
func (l *List) HasKeys() bool {
	v := l.cur.Load()
	return len(v.keys) > 0 || len(v.keyEdits) > 0
}

// Size reports how many blocks were read for each kind, and whether every
// block in force was.
func (l *List) Size() (addrs, keys int, addrsComplete, keysComplete bool) {
	v := l.cur.Load()
	return len(v.addrs), len(v.keys), v.complete[0], v.complete[1]
}

// active reports whether a block that ends at until is in force now.
func active(until int64) bool {
	switch until {
	case Released:
		return false
	case Forever:
		return true
	}
	return time.Now().UnixNano() < until
}

// NoteAddress records this node's block of a until then, or its release
// (Released), written to the database already.
func (l *List) NoteAddress(a netip.Addr, until int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	next := *l.cur.Load()
	next.addrEdits, next.addrs = noteEdit(l, next.addrEdits, next.addrs, a, until)
	l.cur.Store(&next)
}

// NoteKey is NoteAddress for a fingerprint key.
func (l *List) NoteKey(key string, until int64) {
	if len(key) > l.bounds.KeyBytes {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	next := *l.cur.Load()
	next.keyEdits, next.keys = noteEdit(l, next.keyEdits, next.keys, key, until)
	l.cur.Store(&next)
}

// noteEdit returns the edits and the base with one more write, copying what
// it changes; l.mu is held. With the edits full a block is left to the
// lookups -- the cache and the database have it -- while a release, which
// must never be undone by the base, is applied to a copy of the base, and a
// read begun before it is discarded rather than applied.
func noteEdit[K comparable](l *List, edits map[K]edit, base map[K]int64, k K, until int64) (map[K]edit, map[K]int64) {
	if _, held := edits[k]; held || len(edits) < l.bounds.Edits {
		edits = maps.Clone(edits)
		if edits == nil {
			edits = map[K]edit{}
		}
		edits[k] = edit{until: until, seq: l.seq}
		return edits, base
	}
	if until != Released {
		return edits, base
	}
	if _, inBase := base[k]; inBase {
		base = maps.Clone(base)
		delete(base, k)
	}
	l.discardBefore = l.seq
	return edits, base
}

// Token marks when a read of the database began.
type Token struct{ seq uint64 }

// Begin is called before the database is read for Replace.
func (l *List) Begin() Token {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Token{seq: l.seq}
}
