// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"sync"
	"testing"
	"time"
)

func newBroadcaster() *Broadcaster {
	return &Broadcaster{subscribers: make(map[chan AuditEntry]struct{})}
}

func TestSubscriberReceivesBroadcasts(t *testing.T) {
	b := newBroadcaster()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	b.Broadcast(AuditEntry{Action: "login"})

	select {
	case got := <-ch:
		if got.Action != "login" {
			t.Errorf("Action = %q, want login", got.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber received nothing")
	}
}

func TestUnsubscribeClosesAndStopsDelivery(t *testing.T) {
	b := newBroadcaster()
	ch := b.Subscribe()

	b.Unsubscribe(ch)

	if _, open := <-ch; open {
		t.Error("channel still open after Unsubscribe")
	}
	// Broadcasting after the fact must not send on the closed channel, which
	// would panic and take down whatever goroutine was writing an audit entry.
	b.Broadcast(AuditEntry{Action: "after-unsubscribe"})
}

// Unsubscribe checks membership before closing. Without that check a second call
// closes an already-closed channel and panics -- and the caller most likely to
// double-unsubscribe is a deferred cleanup running after an explicit one.
func TestDoubleUnsubscribeDoesNotPanic(t *testing.T) {
	b := newBroadcaster()
	ch := b.Subscribe()

	b.Unsubscribe(ch)
	b.Unsubscribe(ch)

	// A channel this broadcaster never issued must also be safe.
	b.Unsubscribe(make(chan AuditEntry))
}

// TestFullSubscriberDoesNotBlockTheWriter is the property that matters most
// here. Broadcast runs inside the audit write path, so a subscriber that stops
// reading -- a disconnected dashboard, a wedged SSE stream -- must be dropped
// rather than allowed to stall every subsequent audit entry. The non-blocking
// send is what guarantees that.
func TestFullSubscriberDoesNotBlockTheWriter(t *testing.T) {
	b := newBroadcaster()
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Well past the 1000-entry buffer, with nothing draining it.
		for i := 0; i < 5000; i++ {
			b.Broadcast(AuditEntry{Action: "flood"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Broadcast blocked on a full subscriber; audit writes would stall")
	}
}

// Subscribers come and go while entries are being written, so the whole surface
// has to be safe under -race.
func TestConcurrentSubscribeBroadcastUnsubscribe(t *testing.T) {
	b := newBroadcaster()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ch := b.Subscribe()
				b.Broadcast(AuditEntry{Action: "concurrent"})
				b.Unsubscribe(ch)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			b.Broadcast(AuditEntry{Action: "writer"})
		}
	}()

	wg.Wait()

	if len(b.subscribers) != 0 {
		t.Errorf("%d subscribers left registered; they leak until the process exits", len(b.subscribers))
	}
}
