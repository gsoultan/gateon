// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package blocklist

import (
	"net/netip"
	"testing"
	"time"
)

var testBounds = Bounds{Entries: 4, KeyBytes: 16, Edits: 2}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func soon() int64  { return time.Now().Add(time.Hour).UnixNano() }
func ended() int64 { return time.Now().Add(-time.Second).UnixNano() }

// read replaces l's base with the given address blocks, as one read begun now.
func read(t *testing.T, l *List, blocks map[string]int64) {
	t.Helper()
	tok := l.Begin()
	b := l.NewBase()
	for a, until := range blocks {
		b.AddAddress(addr(a), until)
	}
	if !l.Replace(tok, b) {
		t.Fatal("a read was discarded")
	}
}

func TestABlockReadIsEnforcedUntilItEnds(t *testing.T) {
	l := New(testBounds)
	if l.HasAddresses() || l.HasKeys() || l.AddressBlocked(addr("192.0.2.1")) {
		t.Fatal("an empty list answered")
	}
	read(t, l, map[string]int64{"192.0.2.1": Forever, "192.0.2.2": soon(), "192.0.2.3": ended()})
	for a, want := range map[string]bool{"192.0.2.1": true, "192.0.2.2": true, "192.0.2.3": false, "192.0.2.4": false} {
		if got := l.AddressBlocked(addr(a)); got != want {
			t.Errorf("%s: blocked %v, want %v", a, got, want)
		}
	}
	if n, _, complete, _ := l.Size(); n != 3 || !complete {
		t.Errorf("Size = %d, complete %v; want 3, true", n, complete)
	}
}

// This node's release masks the base until a read that saw it, and a read
// begun before the release does not bring the block back.
func TestAReleaseIsNotUndoneByAReadBegunBeforeIt(t *testing.T) {
	l := New(testBounds)
	read(t, l, map[string]int64{"192.0.2.1": Forever})
	stale := l.Begin() // a read that has not seen the release yet
	l.NoteAddress(addr("192.0.2.1"), Released)
	if l.AddressBlocked(addr("192.0.2.1")) {
		t.Fatal("released, and still blocked")
	}
	b := l.NewBase()
	b.AddAddress(addr("192.0.2.1"), Forever) // what that read found
	l.Replace(stale, b)
	if l.AddressBlocked(addr("192.0.2.1")) {
		t.Fatal("a read begun before the release brought the block back")
	}
	read(t, l, map[string]int64{}) // a read that saw it
	if l.AddressBlocked(addr("192.0.2.1")) {
		t.Fatal("released, and blocked after a later read")
	}
	if _, held := l.cur.Load().addrEdits[addr("192.0.2.1")]; held {
		t.Fatal("an edit the read saw was kept")
	}
}

// This node's block is enforced before any read has it.
func TestThisNodesBlockIsEnforcedBeforeTheNextRead(t *testing.T) {
	l := New(testBounds)
	l.NoteAddress(addr("2001:db8::"), soon())
	l.NoteKey("class|198.51.100", Forever)
	if !l.AddressBlocked(addr("2001:db8::")) || !l.KeyBlocked("class|198.51.100") {
		t.Fatal("a block this node wrote was not enforced")
	}
	if !l.HasAddresses() || !l.HasKeys() {
		t.Fatal("the list reported itself empty")
	}
}

// Past the edits bound a block is left to the lookups, and a release is
// applied to the base, discarding any read begun before it.
func TestEditsPastTheBoundStayCorrect(t *testing.T) {
	l := New(testBounds)
	read(t, l, map[string]int64{"192.0.2.9": Forever})
	stale := l.Begin()
	l.NoteAddress(addr("192.0.2.1"), Forever)
	l.NoteAddress(addr("192.0.2.2"), Forever)
	l.NoteAddress(addr("192.0.2.3"), Forever) // past the bound: not held
	if l.AddressBlocked(addr("192.0.2.3")) {
		t.Fatal("an edit past the bound was held")
	}
	l.NoteAddress(addr("192.0.2.1"), Released) // already held: replaced in place
	if l.AddressBlocked(addr("192.0.2.1")) {
		t.Fatal("a release of a held edit did not take")
	}
	l.NoteAddress(addr("192.0.2.9"), Released) // past the bound: applied to the base
	if l.AddressBlocked(addr("192.0.2.9")) {
		t.Fatal("a release past the bound did not lift the block")
	}
	b := l.NewBase()
	b.AddAddress(addr("192.0.2.9"), Forever)
	if l.Replace(stale, b) {
		t.Fatal("a read begun before a release applied to the base was applied")
	}
	if l.AddressBlocked(addr("192.0.2.9")) {
		t.Fatal("the stale read brought the block back")
	}
}

// A list larger than the bound is read up to the bound and says so; a key
// longer than the bound is left out.
func TestTheBaseHoldsNoMoreThanItsBounds(t *testing.T) {
	l := New(testBounds)
	b := l.NewBase()
	for i := range 6 {
		ok := b.AddAddress(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), Forever)
		if want := i < testBounds.Entries; ok != want {
			t.Fatalf("AddAddress #%d = %v, want %v", i, ok, want)
		}
	}
	if !b.AddKey("0123456789abcdefXX", Forever) {
		t.Fatal("an overlong key stopped the read")
	}
	b.AddKey("short", Forever)
	l.Replace(l.Begin(), b)
	n, k, addrsComplete, keysComplete := l.Size()
	if n != testBounds.Entries || k != 1 || addrsComplete || keysComplete {
		t.Fatalf("Size = %d, %d, %v, %v; want %d, 1, false, false", n, k, addrsComplete, keysComplete, testBounds.Entries)
	}
	if l.KeyBlocked("0123456789abcdefXX") {
		t.Fatal("an overlong key was held")
	}
	l.NoteKey("0123456789abcdefXX", Forever)
	if l.KeyBlocked("0123456789abcdefXX") {
		t.Fatal("an overlong key was held as an edit")
	}
	full := l.NewBase()
	for i := range 5 {
		ok := full.AddKey(string(rune('a'+i)), Forever)
		if want := i < testBounds.Entries; ok != want {
			t.Fatalf("AddKey #%d = %v, want %v", i, ok, want)
		}
	}
}
