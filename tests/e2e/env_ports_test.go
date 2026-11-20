// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import (
	"net"
	"testing"
)

// Every port in one environment must differ. Allocated one at a time, Linux
// handed out a duplicate in about 1 set of 6 in 500, enough to fail a few
// percent of CI runs: management and the TLS entrypoint shared a port, and the
// gateway answered TLS clients in plain HTTP. 3000 sets would show a duplicate
// from that allocator with near certainty on Linux; holding the listeners
// together makes one impossible.
func TestGetFreePortsAreDistinctWithinASet(t *testing.T) {
	names := []string{"mgmt", "http_plain", "http_tls", "grpc", "tcp", "mock_backend"}
	for i := range 3000 {
		ports := getFreePorts(t, names...)
		seen := make(map[int]string, len(ports))
		for name, p := range ports {
			if other, dup := seen[p]; dup {
				t.Fatalf("set %d: %s and %s were both given port %d", i, other, name, p)
			}
			seen[p] = name
		}
		if len(ports) != len(names) {
			t.Fatalf("set %d: got %d ports for %d names", i, len(ports), len(names))
		}
	}
}

// A port handed to the environment must reach the config unchanged. The
// placeholders were replaced one after another, each pass over the output of
// the last, so an allocated port that contained a later placeholder was
// rewritten again: TLS given 38085 became 338899 once 8085 was replaced with
// the gRPC port 38899, the gateway could not bind it, and
// TestFingerprintBlocking timed out waiting for 38085 in the scheduled race run.
func TestPatchPortsNeverRewritesAnAllocatedPort(t *testing.T) {
	ports := map[string]int{
		"mgmt":         28282,
		"http_plain":   48080,
		"http_tls":     38085,
		"grpc":         38899,
		"tcp":          18082,
		"mock_backend": 58081,
	}
	in := `"mgmt": ":8080", "plain": ":8081", "tls": "127.0.0.1:8282", ` +
		`"grpc": ":8085", "tcp": ":8086", "backend": "http://127.0.0.1:8082"`
	want := `"mgmt": ":28282", "plain": ":48080", "tls": "127.0.0.1:38085", ` +
		`"grpc": ":38899", "tcp": ":18082", "backend": "http://127.0.0.1:58081"`
	if got := patchPorts(in, ports); got != want {
		t.Fatalf("patchPorts rewrote an allocated port:\n got %s\nwant %s", got, want)
	}
}

// waitForPortRelease is what load_test relies on between two gateway runs on
// the same ports; it must come back as soon as the port stops answering, and
// not before. The listener here closes only after the helper has connected to
// it at least once, so a helper that returned without waiting would be caught
// by the accept never happening.
func TestWaitForPortReleaseReturnsOnceTheListenerCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		close(accepted)
		_ = ln.Close()
	}()

	waitForPortRelease(t, port)

	select {
	case <-accepted:
	default:
		t.Fatal("waitForPortRelease returned while the port was still accepting connections")
	}
}

func TestWaitForPortReleaseReturnsAtOnceForAClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitForPortRelease(t, port)
}
