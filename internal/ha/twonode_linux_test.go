// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package ha

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// peerOutranks is unit-tested, but a correct decision function is not the same
// as two nodes converging. This runs two managers against real sockets: real
// adverts, encoded, sent, received, authenticated and acted on. The only thing
// stubbed is the address each believes it has, because two managers on one host
// genuinely share one.
//
// Opt-in and Linux-only: it binds the multicast port and needs a network stack
// that will carry the traffic. Set GATEON_HA_INTEGRATION=1.

func twoNodeManager(t *testing.T, priority int32, localIP string) *HAManager {
	t.Helper()
	m := &HAManager{
		config: &gateonv1.HaConfig{
			Enabled:         true,
			VirtualRouterId: 51,
			Priority:        priority,
			AdvertInt:       1,
			AuthPass:        "shared-secret-for-both-nodes",
			// No VIPs: this is about who decides they are master, not about
			// whether `ip addr add` succeeds. Both would fight over one address.
			VirtualIps: nil,
		},
		localIP: net.ParseIP(localIP),
	}
	return m
}

// runNode starts a manager's advert loop against a real socket and returns a
// stop func. It mirrors Start without the VIP management.
func runNode(t *testing.T, m *HAManager) func() {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", "224.0.0.18:8946")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 8946})
		if err != nil {
			t.Skipf("cannot bind the advert port (%v); needs a usable network stack", err)
		}
	}
	m.udpConn = conn

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.lastSeen = time.Now()
	m.mu.Unlock()

	go m.listenLoop(ctx, []byte(m.config.AuthPass), replayWindow(time.Second))
	go func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				m.step(ctx)
			}
		}
	}()

	return func() {
		cancel()
		_ = conn.Close()
	}
}

// TestSingleNodeElection runs one node and reports whether it ended up master.
//
// The election has to be exercised across two processes with genuinely distinct
// source addresses: peerOutranks compares the advert's source IP against this
// node's own, and two managers sharing a process share a source address, so both
// reach the same verdict and both yield. Running one node per container gives
// each a real address and makes the comparison mean something.
//
// Driven by the harness in doc/ha-two-node-check.md; each container runs this
// with its own GATEON_HA_PRIORITY and prints a verdict the harness compares.
func TestSingleNodeElection(t *testing.T) {
	if os.Getenv("GATEON_HA_INTEGRATION") == "" {
		t.Skip("set GATEON_HA_INTEGRATION=1 to run a node against real sockets")
	}

	priority := int32(100)
	if v := os.Getenv("GATEON_HA_PRIORITY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("GATEON_HA_PRIORITY=%q: %v", v, err)
		}
		priority = int32(n)
	}

	iface := os.Getenv("GATEON_HA_IFACE")
	if iface == "" {
		iface = "eth0"
	}

	m := twoNodeManager(t, priority, "")
	m.config.Interface = iface
	m.localIP = haInterfaceIP(iface)
	if m.localIP == nil {
		t.Fatalf("no usable IPv4 address on %s; the tie-break has nothing to compare", iface)
	}
	t.Logf("node: priority=%d addr=%s", priority, m.localIP)

	stop := runNode(t, m)
	defer stop()

	// Long enough to time out waiting for a master, advertise, and settle.
	time.Sleep(12 * time.Second)

	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()

	verdict := "BACKUP"
	if active {
		verdict = "MASTER"
	}
	// The harness greps for this line.
	t.Logf("HA_VERDICT %s addr=%s priority=%d dropped=%d",
		verdict, m.localIP, priority, m.DroppedAdverts())
}

// A node whose peer holds a different auth pass must not be able to influence
// it, and both then believe they are master -- which is correct: they are not
// in the same cluster.
func TestMismatchedSecretsDoNotFormACluster(t *testing.T) {
	if os.Getenv("GATEON_HA_INTEGRATION") == "" {
		t.Skip("set GATEON_HA_INTEGRATION=1 to run two managers against real sockets")
	}

	a := twoNodeManager(t, 100, "10.0.0.1")
	b := twoNodeManager(t, 100, "10.0.0.2")
	b.config.AuthPass = "a-different-secret"

	stopA := runNode(t, a)
	defer stopA()
	stopB := runNode(t, b)
	defer stopB()

	time.Sleep(6 * time.Second)

	if a.DroppedAdverts() == 0 && b.DroppedAdverts() == 0 {
		t.Error("neither node rejected the other's adverts; the shared secret is not being checked")
	}
	t.Logf("dropped adverts a=%d b=%d", a.DroppedAdverts(), b.DroppedAdverts())
}
