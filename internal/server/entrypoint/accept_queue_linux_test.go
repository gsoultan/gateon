// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// waitForAccept returns once the listening socket at addr has no connection
// waiting in its accept queue: the kernel completes a client's handshake
// before the server's Accept takes the connection, so net.Dial returning says
// nothing about whether the server holds it yet. A connection still in the
// queue when the listener closes is reset by the kernel, which no shutdown
// logic can answer. Linux reports the queue length as rx_queue of the LISTEN
// row in /proc/net/tcp.
func waitForAccept(t *testing.T, addr net.Addr) {
	t.Helper()
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp.IP.To4() == nil {
		t.Fatalf("waitForAccept reads /proc/net/tcp and needs an IPv4 TCP address, got %v", addr)
	}
	local := fmt.Sprintf("%08X:%04X", ipv4ProcOrder(tcp.IP.To4()), tcp.Port)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for deadline := time.Now().Add(shutdownBound); ; <-tick.C {
		queued, err := acceptQueue(local)
		if err != nil {
			t.Fatalf("read the accept queue: %v", err)
		}
		if queued == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server never accepted a connection waiting at %v", addr)
		}
	}
}

// ipv4ProcOrder is ip as /proc/net/tcp prints it: the address in host byte
// order, which on the little-endian hosts CI runs on reverses it.
func ipv4ProcOrder(ip net.IP) uint32 {
	return uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])
}

// acceptQueue is how many connections wait in the accept queue of the LISTEN
// socket bound to local, in /proc/net/tcp's address:port form.
func acceptQueue(local string) (int, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// sl local_address rem_address st tx_queue:rx_queue ...
		if len(fields) < 5 || fields[1] != local || fields[3] != "0A" {
			continue
		}
		_, rx, ok := strings.Cut(fields[4], ":")
		if !ok {
			return 0, fmt.Errorf("unreadable queue field %q", fields[4])
		}
		n, err := strconv.ParseInt(rx, 16, 64)
		return int(n), err
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no listening socket at %s", local)
}
