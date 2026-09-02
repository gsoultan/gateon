// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import "testing"

// configHash is what tells the resolver a cached pool is stale. Every property
// below is really a statement about when live traffic gets moved to a new set of
// backends, and when it does not.

func cfg(mut func(*L4Config)) *L4Config {
	c := &L4Config{
		LoadBalancer:        "round_robin",
		HealthCheckInterval: 10000,
		HealthCheckTimeout:  3000,
		UDPSessionTimeout:   60,
		UDPMaxSessions:      4096,
		Backends:            []string{"10.0.0.1:80", "10.0.0.2:80"},
	}
	if mut != nil {
		mut(c)
	}
	return c
}

// TestDifferentBackendSetsDoNotCollide is the regression guard. The hash used to
// concatenate bare strings, so the byte stream was ambiguous: {"ab","c"} and
// {"a","bc"} produced the same value. A collision means a backend change does
// not look like a change, and the resolver goes on serving the old pool.
func TestDifferentBackendSetsDoNotCollide(t *testing.T) {
	a := cfg(func(c *L4Config) { c.Backends = []string{"ab", "c"} })
	b := cfg(func(c *L4Config) { c.Backends = []string{"a", "bc"} })

	if configHash(a) == configHash(b) {
		t.Fatal(`{"ab","c"} and {"a","bc"} hash identically; a backend change would not refresh the pool`)
	}
}

// The same ambiguity across the scalar fields: adjacent values must not be able
// to run together into the same bytes.
func TestAdjacentScalarsDoNotCollide(t *testing.T) {
	a := cfg(func(c *L4Config) { c.HealthCheckInterval = 1; c.HealthCheckTimeout = 23 })
	b := cfg(func(c *L4Config) { c.HealthCheckInterval = 12; c.HealthCheckTimeout = 3 })

	if configHash(a) == configHash(b) {
		t.Fatal("different health-check timings hash identically")
	}
}

// Every field has to participate, or changing it silently keeps the old pool.
func TestEveryFieldChangesTheHash(t *testing.T) {
	base := configHash(cfg(nil))

	for _, tc := range []struct {
		name string
		mut  func(*L4Config)
	}{
		{"load balancer", func(c *L4Config) { c.LoadBalancer = "least_conn" }},
		{"health check interval", func(c *L4Config) { c.HealthCheckInterval = 5000 }},
		{"health check timeout", func(c *L4Config) { c.HealthCheckTimeout = 1000 }},
		{"udp session timeout", func(c *L4Config) { c.UDPSessionTimeout = 30 }},
		{"udp max sessions", func(c *L4Config) { c.UDPMaxSessions = 128 }},
		{"proxy protocol", func(c *L4Config) { c.ProxyProtocol = true }},
		{"a backend added", func(c *L4Config) { c.Backends = append(c.Backends, "10.0.0.3:80") }},
		{"a backend removed", func(c *L4Config) { c.Backends = c.Backends[:1] }},
		{"a backend changed", func(c *L4Config) { c.Backends[0] = "10.0.0.9:80" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if configHash(cfg(tc.mut)) == base {
				t.Errorf("changing the %s did not change the hash, so the pool would not be rebuilt", tc.name)
			}
		})
	}
}

// Reordering a round-robin list is not a change worth tearing down live
// connections for, so the hash is deliberately order-insensitive.
func TestBackendOrderDoesNotChangeTheHash(t *testing.T) {
	a := cfg(func(c *L4Config) { c.Backends = []string{"10.0.0.1:80", "10.0.0.2:80"} })
	b := cfg(func(c *L4Config) { c.Backends = []string{"10.0.0.2:80", "10.0.0.1:80"} })

	if configHash(a) != configHash(b) {
		t.Error("reordering backends rebuilt the pool; that drops live connections for no change")
	}
}

// Hashing must not reorder the caller's slice. The config is shared, and a
// surprise mutation from a read-only-looking call is the kind of thing that
// shows up much later as an unrelated bug.
func TestHashingDoesNotMutateTheConfig(t *testing.T) {
	c := cfg(func(c *L4Config) { c.Backends = []string{"z:1", "a:1"} })
	_ = configHash(c)

	if c.Backends[0] != "z:1" || c.Backends[1] != "a:1" {
		t.Errorf("configHash reordered the caller's backends: %v", c.Backends)
	}
}

func TestIdenticalConfigsAgree(t *testing.T) {
	// Assigned rather than compared inline: staticcheck reads f() != f() as a
	// mistake (SA4000), and here the repeated call is the assertion.
	first := configHash(cfg(nil))
	second := configHash(cfg(nil))
	if first != second {
		t.Fatal("the same configuration hashed differently; every lookup would miss")
	}
}
