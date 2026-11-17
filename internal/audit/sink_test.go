// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"sync"
	"testing"
)

// A sink sees every stored entry, the management ones and the system ones the
// writer batches, signed as stored -- which is what lets a copy kept off the
// host be verified against the chain (ADR 0099).
func TestSinkSeesEveryStoredEntry(t *testing.T) {
	m := newTestManager(t, signingConfig("sink-test-key"))
	m.startWriter()
	t.Cleanup(func() { close(m.stop); <-m.writerDone })

	var mu sync.Mutex
	var got []AuditEntry
	remove := AddSink(func(e AuditEntry) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	defer remove()

	m.log(context.Background(), "admin", "update", "user", "Updated user x", "192.0.2.1")
	m.logSystem(systemEntry{action: "waf_block", resource: "/", details: "d", ip: "198.51.100.7"})
	ack := make(chan struct{})
	m.flushReq <- ack
	<-ack

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("sink saw %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Action != "update" || got[1].Action != "waf_block" {
		t.Fatalf("sink saw %q then %q, want update then waf_block", got[0].Action, got[1].Action)
	}
	for _, e := range got {
		if e.Signature == "" {
			t.Fatalf("entry %q reached the sink unsigned; an off-host copy could not be verified", e.Action)
		}
	}
	if got[1].PreviousHash != got[0].Signature {
		t.Fatal("the sink's copy does not chain: the second entry's previous hash is not the first's signature")
	}
}

// An entry the log refuses -- audit switched off -- is not handed on either.
func TestSinkSeesNothingWhenAuditIsOff(t *testing.T) {
	m := newTestManager(t, signingConfig("k"))
	m.config.Enabled = false
	n := 0
	remove := AddSink(func(AuditEntry) { n++ })
	defer remove()
	m.log(context.Background(), "admin", "update", "user", "x", "")
	if n != 0 {
		t.Fatalf("sink saw %d entries with audit off", n)
	}
}

func TestRemovedSinkStopsReceiving(t *testing.T) {
	m := newTestManager(t, signingConfig("k"))
	n := 0
	remove := AddSink(func(AuditEntry) { n++ })
	m.log(context.Background(), "admin", "a", "r", "d", "")
	remove()
	m.log(context.Background(), "admin", "a", "r", "d", "")
	if n != 1 {
		t.Fatalf("sink saw %d entries, want 1 (the one before it was removed)", n)
	}
}
