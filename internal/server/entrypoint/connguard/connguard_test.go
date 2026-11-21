// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package connguard

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type fakeConn struct{ closed atomic.Bool }

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

var addrA = netip.MustParseAddr("10.99.0.2")

// One address may hold only a few connections that have sent nothing; the
// cap is per address, and proving or closing one gives its place back.
func TestAnAddressHoldsOnlyItsLimitOfUnprovenConnections(t *testing.T) {
	u := NewUnproven(2, time.Hour, time.Hour)
	e1, ok1 := u.Admit(&fakeConn{}, addrA, true, false)
	_, ok2 := u.Admit(&fakeConn{}, addrA, true, false)
	_, ok3 := u.Admit(&fakeConn{}, addrA, true, false)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("admitted %t %t %t, want the third refused", ok1, ok2, ok3)
	}
	if _, ok := u.Admit(&fakeConn{}, netip.MustParseAddr("10.99.0.3"), true, false); !ok {
		t.Fatal("another address was refused")
	}
	if _, ok := u.Admit(&fakeConn{}, addrA, false, false); !ok {
		t.Fatal("an exempt connection was counted against the address")
	}
	e1.Prove()
	if _, ok := u.Admit(&fakeConn{}, addrA, true, false); !ok {
		t.Fatal("a proven connection still held its address's place")
	}
}

// A full entrypoint closes the connection that has waited longest without a
// request, so a newcomer gets its slot (review D1).
func TestEvictionClosesTheOldestUnprovenConnection(t *testing.T) {
	u := NewUnproven(8, time.Hour, time.Hour)
	old, mid, proven := &fakeConn{}, &fakeConn{}, &fakeConn{}
	ep, _ := u.Admit(proven, addrA, true, false)
	u.Admit(old, addrA, true, false)
	u.Admit(mid, addrA, true, false)
	ep.Prove()
	if !u.EvictOldest() || !old.closed.Load() || mid.closed.Load() || proven.closed.Load() {
		t.Fatalf("closed old %t mid %t proven %t; want only the oldest unproven",
			old.closed.Load(), mid.closed.Load(), proven.closed.Load())
	}
	if !u.EvictOldest() || !mid.closed.Load() || u.EvictOldest() {
		t.Fatal("eviction did not walk the unproven connections in order and stop")
	}
}

// An unproven connection is closed at its deadline, the shorter one when it
// was admitted under pressure; a proven one is not.
func TestAnUnprovenConnectionIsClosedAtItsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u := NewUnproven(8, 5*time.Second, time.Second)
		calm, pressed, proven := &fakeConn{}, &fakeConn{}, &fakeConn{}
		u.Admit(calm, addrA, true, false)
		u.Admit(pressed, addrA, true, true)
		e, _ := u.Admit(proven, addrA, true, false)
		e.Prove()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !pressed.closed.Load() || calm.closed.Load() {
			t.Fatalf("after 2s: pressured closed %t, calm closed %t", pressed.closed.Load(), calm.closed.Load())
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if !calm.closed.Load() || proven.closed.Load() {
			t.Fatalf("after 6s: calm closed %t, proven closed %t", calm.closed.Load(), proven.closed.Load())
		}
	})
}

func TestANilTrackerAdmitsEverything(t *testing.T) {
	u := NewUnproven(0, time.Second, time.Second)
	if u != nil {
		t.Fatal("a zero limit built a tracker")
	}
	e, ok := u.Admit(&fakeConn{}, addrA, true, false)
	if !ok || u.EvictOldest() {
		t.Fatal("a nil tracker refused or evicted")
	}
	e.Prove()
	e.Forget()
}

// A connection that cancels more streams in a second than its limit trips
// once; one that stays under it, second after second, never does.
func TestResetsTripOncePastTheLimit(t *testing.T) {
	var r Resets
	r.Init(3)
	now := time.Unix(1000, 0)
	trips := 0
	for range 10 {
		if r.Note(now) {
			trips++
		}
	}
	if trips != 1 {
		t.Fatalf("tripped %d times, want once", trips)
	}
	var calm Resets
	calm.Init(3)
	for s := range 10 {
		for range 3 {
			if calm.Note(time.Unix(int64(2000+s), 0)) {
				t.Fatal("a connection under its limit tripped")
			}
		}
	}
	var off Resets
	for range 100 {
		if off.Note(now) {
			t.Fatal("a guard with no limit tripped")
		}
	}
}
