// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package discovery

import (
	"net/url"
	"testing"
)

// TestTargetURLIsAlwaysParseable is the property that matters: whatever a
// discovery backend reports, the load balancer has to be able to dial it. An
// IPv6 address formatted as "http://2001:db8::1:80" parses as garbage or not at
// all, and the failure mode is a backend that silently never gets traffic.
func TestTargetURLIsAlwaysParseable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		host     string
		port     int
		wantHost string
	}{
		{"ipv4 with port", "10.0.0.1", 8080, "10.0.0.1:8080"},
		{"ipv4 no port", "10.0.0.1", 0, "10.0.0.1"},
		{"hostname with port", "backend.svc.local", 9000, "backend.svc.local:9000"},
		{"hostname no port", "backend.svc.local", 0, "backend.svc.local"},
		{"ipv6 with port", "2001:db8::1", 8080, "[2001:db8::1]:8080"},
		{"ipv6 no port", "2001:db8::1", 0, "[2001:db8::1]"},
		{"ipv6 loopback", "::1", 443, "[::1]:443"},
		{"ipv4-mapped ipv6", "::ffff:10.0.0.1", 80, "[::ffff:10.0.0.1]:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := targetURL(tc.host, tc.port)
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("targetURL(%q, %d) = %q, which does not parse: %v",
					tc.host, tc.port, raw, err)
			}
			if u.Host != tc.wantHost {
				t.Errorf("targetURL(%q, %d) = %q, host = %q, want %q",
					tc.host, tc.port, raw, u.Host, tc.wantHost)
			}
			if u.Scheme != "http" {
				t.Errorf("scheme = %q, want http", u.Scheme)
			}
		})
	}
}

// TestSRVWeightPrefersLowerPriority pins RFC 2782's direction. The formula this
// replaced was priority*10 + weight, which ranked a priority-20 backup above a
// priority-0 primary -- discovery preferred exactly the hosts the record author
// marked last resort.
func TestSRVWeightPrefersLowerPriority(t *testing.T) {
	t.Parallel()

	primary := srvWeight(0, 10)
	backup := srvWeight(20, 100)

	if primary <= backup {
		t.Errorf("priority 0 weighted %d, priority 20 weighted %d; "+
			"RFC 2782 says the lower priority number must be preferred",
			primary, backup)
	}
}

// TestSRVWeightPriorityDominatesWeight checks that no weight difference can
// close a priority gap, which is what "MUST attempt the lowest-numbered
// priority" requires.
func TestSRVWeightPriorityDominatesWeight(t *testing.T) {
	t.Parallel()

	// Maximum possible weight at the worse priority against minimum at the
	// better one.
	better := srvWeight(1, 0)
	worse := srvWeight(2, 65535)

	if better <= worse {
		t.Errorf("priority 1 weight 0 scored %d, priority 2 weight 65535 scored %d; "+
			"a weight difference must never outrank a priority difference",
			better, worse)
	}
}

// TestSRVWeightOrdersWithinAPriority checks the tiebreak still works: SRV
// weight is a relative share among hosts of equal priority.
func TestSRVWeightOrdersWithinAPriority(t *testing.T) {
	t.Parallel()

	if heavy, light := srvWeight(5, 200), srvWeight(5, 10); heavy <= light {
		t.Errorf("at equal priority, weight 200 scored %d and weight 10 scored %d; "+
			"the heavier share must rank higher", heavy, light)
	}
}

// TestSRVWeightSurvivesExtremePriorities guards the clamp. A uint16 priority of
// 65535 is legal, and an unclamped (max-p) would go sharply negative and land a
// last-resort host above the primary -- reintroducing the original bug from the
// other end.
func TestSRVWeightSurvivesExtremePriorities(t *testing.T) {
	t.Parallel()

	best := srvWeight(0, 0)
	for _, p := range []uint16{15, 16, 17, 1000, 65535} {
		if got := srvWeight(p, 65535); got >= best {
			t.Errorf("priority %d scored %d, which is not below priority 0's %d",
				p, got, best)
		}
		if got := srvWeight(p, 0); got < 0 {
			t.Errorf("priority %d scored %d; a negative weight underflows the "+
				"load balancer's share calculation", p, got)
		}
	}
}
