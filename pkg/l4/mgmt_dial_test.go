// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/gsoultan/gateon/internal/mgmtaddr"
)

// TestATCPServiceDoesNotConnectToTheManagementListener (ADR 0052, review
// finding MGMT-N2): an L4 route carries no request the management listener
// could tell apart, so a TCP service pointed at it handed the dashboard and API
// to anyone who reached the entrypoint, from loopback. The backend connection
// is refused -- here by the name localhost, as a name that later resolves to
// this host would be -- and the health check counts the backend down instead
// of up.
func TestATCPServiceDoesNotConnectToTheManagementListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	unregister := mgmtaddr.RegisterListener(ln.Addr())
	defer unregister()
	addr := net.JoinHostPort("localhost", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))

	p := NewTCPBackendPool([]string{addr}, "round_robin", 10000, 1000, false)
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	b, err := p.DialBackend(context.Background(), client)
	if !errors.Is(err, mgmtaddr.ErrManagementListener) {
		if err == nil {
			b.Close()
		}
		t.Fatalf("DialBackend to the management listener: %v, want ErrManagementListener", err)
	}
	for range tcpFailThreshold {
		p.healthCheck()
	}
	if p.alive[0].Load() {
		t.Error("the health check still counts a backend on the management listener as up")
	}
}
