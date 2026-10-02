// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package e2e

import "testing"

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
