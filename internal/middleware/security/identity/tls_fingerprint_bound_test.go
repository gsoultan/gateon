// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"strconv"
	"testing"
)

// fakeConn carries only a remote address, which is all getAddr reads.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.remote }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// TestFingerprintShardsAreBounded pins the ceiling on a map keyed by the
// client's IP:port and written from the TLS handshake callback.
//
// RemoveFingerprints has one non-test caller, the http.Server ConnState hook,
// so the HTTP/3 listener (no ConnState) and the bare TCP accept loop both
// wrote entries nothing ever removed. One QUIC Initial packet, or a TCP
// connect plus ClientHello and a reset, minted a permanent entry -- and
// ephemeral source ports make every reconnect from one address a new key.
func TestFingerprintShardsAreBounded(t *testing.T) {
	// This test deliberately fills every shard, so it has to put them back.
	// Without this it leaves the table full for whatever runs next, and the
	// next test's insert is refused by the very bound under test -- which is
	// the order-dependence shape, created by the test written to check a fix
	// for it.
	t.Cleanup(resetFingerprintShards)

	// Work within one shard by reusing its index: getShard hashes the address,
	// so this just floods every shard and checks none exceeds the cap.
	for i := range maxFingerprintsPerShard * numShards * 2 {
		conn := &fakeConn{remote: fakeAddr("198.51.100.1:" + strconv.Itoa(i))}
		SetFingerprints(conn, Fingerprints{JA4: "x"})
	}

	for i, sh := range shards {
		sh.mu.RLock()
		n := len(sh.conns)
		sh.mu.RUnlock()
		if n > maxFingerprintsPerShard {
			t.Errorf("shard %d holds %d entries, cap is %d: a handshake flood "+
				"grows this map without limit and nothing evicts it",
				i, n, maxFingerprintsPerShard)
		}
	}
}

// TestFingerprintOverwriteDoesNotConsumeBudget keeps the bound from refusing
// updates to connections it is already tracking -- a renegotiation or a second
// SNI callback on the same connection must still update.
func TestFingerprintOverwriteDoesNotConsumeBudget(t *testing.T) {
	conn := &fakeConn{remote: fakeAddr("203.0.113.77:1234")}
	SetFingerprints(conn, Fingerprints{JA4: "first"})
	SetFingerprints(conn, Fingerprints{JA4: "second"})

	got := GetFingerprints(conn)
	if got.JA4 != "second" {
		t.Errorf("JA4 = %q, want %q: an update to a tracked connection was "+
			"refused as if it were a new one", got.JA4, "second")
	}
}

// resetFingerprintShards empties every shard, so a test that fills them does
// not decide what the next one sees.
func resetFingerprintShards() {
	for _, sh := range shards {
		sh.mu.Lock()
		sh.conns = make(map[string]Fingerprints)
		sh.mu.Unlock()
	}
}
