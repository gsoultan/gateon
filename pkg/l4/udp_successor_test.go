// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"testing"
	"time"
)

// TestUDPSessionProxy_AnExpiredSessionDoesNotTakeItsSuccessorWithIt: a
// session's reader goroutine removed the session's *key* from the table when
// its socket was closed. Expiry closes the socket and deletes the key under
// the lock, and the same client's next packet -- which arrives before the
// reader has woken, whenever expiry ran inline because the table was full --
// creates a new session under that key. The reader then deleted the new
// session from the table: its socket and goroutine stayed alive with nothing
// able to reach them, and the client's next packet created a third. Each
// occurrence leaked a descriptor, a goroutine and a 64KiB buffer. The reader
// now removes only the entry that is still its own.
func TestUDPSessionProxy_AnExpiredSessionDoesNotTakeItsSuccessorWithIt(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)
	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, 4)
	t.Cleanup(p.Stop)

	client := spoofedAddr(1)
	key := client.String()
	p.HandlePacket(server, client, []byte("first"))

	// Hold the lock across the expiry and the client's return, so the old
	// reader -- woken by the close -- cannot get in between the two, which is
	// exactly the ordering the inline expiry on a full table produces.
	p.mu.Lock()
	old := p.sessions[key]
	old.lastUsed = time.Now().Add(-2 * time.Hour)
	p.expireLocked(time.Now())
	if _, still := p.sessions[key]; still {
		p.mu.Unlock()
		t.Fatal("the idle session was not expired")
	}
	successor := &udpSession{clientAddr: client, conn: old.conn, lastUsed: time.Now()}
	p.sessions[key] = successor
	p.mu.Unlock()

	// The old reader has the closed socket's error by now and takes the lock
	// next. Give it time to run; without the fix it deletes the successor.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		got := p.sessions[key]
		p.mu.Unlock()
		if got != successor {
			t.Fatalf("the expired session's reader removed its successor from the table")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The successor shares the closed socket only so that nothing is leaked
	// by the test itself; take it out before Stop closes everything.
	p.mu.Lock()
	delete(p.sessions, key)
	p.mu.Unlock()
}
