// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// pkg/l4 had no tests. The UDP session table is the part that most needed them:
// it is keyed by the client's source address, and a UDP source address is
// whatever the sender put in the packet. Nothing verifies it, so "one entry per
// client" is really "one entry per address the sender feels like using", and
// each entry costs a socket, a goroutine and a 64KiB buffer.

// udpEchoBackend gives HandlePacket a real address to dial, so sessions are
// created through the same path production uses rather than a stub.
func udpEchoBackend(t *testing.T) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

// clientConn is the socket HandlePacket would write replies back through.
func clientConn(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func spoofedAddr(i int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(i%256)), Port: 1024 + (i % 60000)}
}

// The bug this bounds: without a ceiling, one sender varying its source address
// allocates a socket, a goroutine and a 64KiB buffer per address, until the
// gateway runs out of descriptors or memory. Idle expiry does not save it —
// above maxSessions/timeout arrivals simply outrun the sweep.
func TestUDPSessionProxy_SessionTableIsBounded(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)

	const cap = 32
	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, cap)
	if p == nil {
		t.Fatal("proxy not created")
	}
	t.Cleanup(p.Stop)

	// Ten times the cap, every packet from a different source.
	for i := range cap * 10 {
		p.HandlePacket(server, spoofedAddr(i), []byte("x"))
	}

	if got := p.Sessions(); got > cap {
		t.Fatalf("session table holds %d entries, above the cap of %d", got, cap)
	}
	if p.DroppedPackets() == 0 {
		t.Fatal("expected refused packets to be counted once the table filled")
	}
}

func TestUDPSessionProxy_DefaultCapApplies(t *testing.T) {
	backend := udpEchoBackend(t)

	p := NewUDPSessionProxy([]string{backend.String()}, "", 0, 0)
	if p == nil {
		t.Fatal("proxy not created")
	}
	t.Cleanup(p.Stop)

	if p.maxSessions != DefaultUDPMaxSessions {
		t.Fatalf("maxSessions = %d, want the default %d", p.maxSessions, DefaultUDPMaxSessions)
	}
}

// An established session must keep working while the table is full. Refusing
// new arrivals is the whole point of choosing refusal over eviction: whoever
// sends the most addresses must not be able to displace a real client.
func TestUDPSessionProxy_EstablishedSessionSurvivesAFlood(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)

	const cap = 8
	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, cap)
	t.Cleanup(p.Stop)

	legit := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5555}
	p.HandlePacket(server, legit, []byte("hello"))

	for i := range cap * 20 {
		p.HandlePacket(server, spoofedAddr(i), []byte("flood"))
	}

	p.mu.Lock()
	_, stillThere := p.sessions[legit.String()]
	p.mu.Unlock()
	if !stillThere {
		t.Fatal("the established session was evicted by the flood")
	}
}

// Idle sessions must be reclaimed, or the cap turns into a permanent ceiling
// that legitimate clients cannot get past after one burst.
func TestUDPSessionProxy_IdleSessionsAreReclaimed(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)

	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, 4)
	t.Cleanup(p.Stop)

	for i := range 4 {
		p.HandlePacket(server, spoofedAddr(i), []byte("x"))
	}
	if got := p.Sessions(); got != 4 {
		t.Fatalf("Sessions = %d, want 4 before expiry", got)
	}

	// Age every session past the timeout without sleeping.
	p.mu.Lock()
	for _, s := range p.sessions {
		s.lastUsed = time.Now().Add(-2 * time.Hour)
	}
	p.mu.Unlock()

	p.expireSessions()

	if got := p.Sessions(); got != 0 {
		t.Fatalf("Sessions = %d, want 0 after every session went idle", got)
	}

	// And the table accepts new clients again.
	p.HandlePacket(server, spoofedAddr(99), []byte("x"))
	if got := p.Sessions(); got != 1 {
		t.Fatalf("Sessions = %d, want 1 after the table drained", got)
	}
}

func TestUDPSessionProxy_NoBackendsYieldsNoProxy(t *testing.T) {
	if p := NewUDPSessionProxy(nil, "round_robin", 0, 0); p != nil {
		t.Fatal("a proxy with no backends must not be created")
	}
}

func TestUDPSessionProxy_PickBackendRoundRobins(t *testing.T) {
	p := &UDPSessionProxy{backendAddrs: []string{"a:1", "b:2", "c:3"}}

	var got []string
	for range 6 {
		got = append(got, p.pickBackend())
	}
	want := []string{"a:1", "b:2", "c:3", "a:1", "b:2", "c:3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pick %d = %q, want %q (sequence %v)", i, got[i], want[i], got)
		}
	}
}

func TestUDPSessionProxy_StopClosesEverySession(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)

	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, 16)
	for i := range 5 {
		p.HandlePacket(server, spoofedAddr(i), []byte("x"))
	}
	if p.Sessions() == 0 {
		t.Fatal("expected sessions before Stop")
	}

	p.Stop()

	if got := p.Sessions(); got != 0 {
		t.Fatalf("Sessions = %d after Stop, want 0", got)
	}
}

// The cap must hold when packets arrive concurrently, which is the only way
// they actually arrive. Run with -race.
func TestUDPSessionProxy_BoundHoldsUnderConcurrentArrivals(t *testing.T) {
	backend := udpEchoBackend(t)
	server := clientConn(t)

	const cap = 24
	p := NewUDPSessionProxy([]string{backend.String()}, "round_robin", 3600, cap)
	t.Cleanup(p.Stop)

	done := make(chan struct{})
	for w := range 8 {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := range 100 {
				p.HandlePacket(server, spoofedAddr(w*1000+i), []byte(fmt.Sprintf("%d", i)))
			}
		}(w)
	}
	for range 8 {
		<-done
	}

	if got := p.Sessions(); got > cap {
		t.Fatalf("session table holds %d entries under concurrency, above the cap of %d", got, cap)
	}
}
