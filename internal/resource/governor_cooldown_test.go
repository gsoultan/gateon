// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"testing"
	"time"
)

// TestMemoryScavengersDoNotRunOnEverySampleOfOneSpell: the scavengers run
// when pressure begins and then at most once per cooldown while it lasts. They
// ran on every five-second sample, and the proxy cache's scavenger discards
// every route's balancer and backend connection pool: under sustained pressure
// -- a 2 GB host near its ceiling, or a busy shared machine -- every request
// after each purge paid for new connections and TLS handshakes, twelve times a
// minute, while the purge relieved nothing it had not relieved the first time.
func TestMemoryScavengersDoNotRunOnEverySampleOfOneSpell(t *testing.T) {
	g := newTestGovernor(fixed(memoryPressurePercent+5), fixed(0))
	start := time.Unix(1_700_000_000, 0)
	now := start
	g.now = func() time.Time { return now }
	runs := 0
	g.RegisterMemoryHook("proxy_cache", func() { runs++ })

	for now.Before(start.Add(memoryScavengeCooldown)) { // one cooldown's worth of samples
		g.check(context.Background())
		now = now.Add(defaultInterval)
	}
	if runs != 1 {
		t.Fatalf("scavengers ran %d times in one cooldown of sustained pressure, want 1", runs)
	}
	g.check(context.Background()) // the cooldown has passed and the pressure has not
	if runs != 2 {
		t.Fatalf("scavengers ran %d times once the cooldown passed under the same pressure, want 2", runs)
	}
}

// TestANewSpellOfMemoryPressureScavengesAtOnce: the cooldown belongs to one
// spell of pressure. Once pressure has gone, the next spell must not wait out
// the last one's cooldown.
func TestANewSpellOfMemoryPressureScavengesAtOnce(t *testing.T) {
	usage := memoryPressurePercent + 5
	g := newTestGovernor(func(context.Context) (float64, error) { return usage, nil }, fixed(0))
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	runs := 0
	g.RegisterMemoryHook("proxy_cache", func() { runs++ })

	g.check(context.Background())
	usage = memoryPressurePercent - 20
	now = now.Add(defaultInterval)
	g.check(context.Background())
	usage = memoryPressurePercent + 5
	now = now.Add(defaultInterval)
	g.check(context.Background())
	if runs != 2 {
		t.Fatalf("a second spell of pressure ten seconds after the first scavenged %d times in all, want 2", runs)
	}
}
