// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package blocklist

import "net/netip"

// Base is one read of the blocks in force, built up and then handed to
// Replace. It holds no more than the list's bounds.
type Base struct {
	bounds    Bounds
	addrs     map[netip.Addr]int64
	keys      map[string]int64
	truncated [2]bool
}

// NewBase starts a read.
func (l *List) NewBase() *Base {
	return &Base{bounds: l.bounds, addrs: map[netip.Addr]int64{}, keys: map[string]int64{}}
}

// AddAddress adds a block of a until then (Forever: until released). It
// reports false once the base is full: the reader stops, and the blocks it did
// not add are left to the lookups.
func (b *Base) AddAddress(a netip.Addr, until int64) bool {
	if len(b.addrs) >= b.bounds.Entries {
		b.truncated[0] = true
		return false
	}
	b.addrs[a] = until
	return true
}

// AddKey adds a block of a fingerprint key until then. A key longer than the
// bound is skipped, and the base no longer holds everything; it reports false
// once the base is full.
func (b *Base) AddKey(key string, until int64) bool {
	if len(b.keys) >= b.bounds.Entries {
		b.truncated[1] = true
		return false
	}
	if len(key) > b.bounds.KeyBytes {
		b.truncated[1] = true
		return true
	}
	b.keys[key] = until
	return true
}

// AddressesCut and KeysCut record that the read found more than it added --
// it stopped at its limit -- so the base does not hold every block in force.
func (b *Base) AddressesCut() { b.truncated[0] = true }

// KeysCut is AddressesCut for fingerprint keys.
func (b *Base) KeysCut() { b.truncated[1] = true }

// Replace makes b the list's base, keeping the edits this node wrote after
// the read began -- the read may have missed them -- and dropping the ones
// before, which it saw. A read begun before a release had to be applied to the
// base itself is discarded: it may hold the block that release lifted. It
// reports whether b was applied.
func (l *List) Replace(t Token, b *Base) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.seq < l.discardBefore {
		return false
	}
	old := l.cur.Load()
	l.cur.Store(&view{
		addrs:     b.addrs,
		keys:      b.keys,
		addrEdits: editsAfter(old.addrEdits, t.seq),
		keyEdits:  editsAfter(old.keyEdits, t.seq),
		complete:  [2]bool{!b.truncated[0], !b.truncated[1]},
	})
	return true
}

// editsAfter is the edits written after seq.
func editsAfter[K comparable](edits map[K]edit, seq uint64) map[K]edit {
	var out map[K]edit
	for k, e := range edits {
		if e.seq > seq {
			if out == nil {
				out = map[K]edit{}
			}
			out[k] = e
		}
	}
	return out
}
