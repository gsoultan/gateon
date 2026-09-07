// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"context"
	"errors"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The VRRP state machine decides which node owns the virtual IP. Getting it
// wrong does not degrade anything gracefully: either two nodes answer on the
// same address, or none does.
//
// step, acquireVIPs and releaseVIPs were all at 0% coverage.

// manager builds a node whose `ip` invocations succeed without touching the
// machine.
//
// The executor is injected rather than left to the real one, because otherwise
// these assertions depend on the host: on a developer's macOS box the command is
// skipped and every takeover "succeeds", and on Linux CI an unprivileged process
// has no eth0, so the same test says the node correctly refused to become
// master. Both are the platform answering, not the state machine.
func manager(t *testing.T, cfg *gateonv1.HaConfig) *HAManager {
	t.Helper()
	return &HAManager{
		config:   cfg,
		lastSeen: time.Now().Add(-time.Hour),
		runIP:    func(...string) error { return nil },
	}
}

// failingManager builds a node whose `ip` invocations all fail, which is what an
// unprivileged process or a missing interface looks like.
func failingManager(t *testing.T, cfg *gateonv1.HaConfig) *HAManager {
	t.Helper()
	return &HAManager{
		config:   cfg,
		lastSeen: time.Now().Add(-time.Hour),
		runIP:    func(...string) error { return errors.New("ip: operation not permitted") },
	}
}

func goodConfig() *gateonv1.HaConfig {
	return &gateonv1.HaConfig{
		Enabled:         true,
		Interface:       "eth0",
		VirtualIps:      []string{"192.0.2.10/24"},
		Priority:        100,
		AdvertInt:       1,
		VirtualRouterId: 51,
		AuthPass:        "shared-secret",
	}
}

// TestNodeDoesNotClaimMasterWhenItCannotHoldTheVIP is the first defect.
//
// step calls acquireVIPs and then sets active = true regardless of what
// happened. acquireVIPs returns without doing anything when the interface is
// empty or its name is invalid, so a misconfigured node marks itself MASTER
// while holding no address.
//
// That is worse than the node simply failing. An active node advertises, and
// every peer that receives an advert it does not outrank refreshes lastSeen and
// stays BACKUP. So the broken node silently suppresses the healthy one, nobody
// holds the VIP, and every node in the cluster reports itself as fine.
func TestNodeDoesNotClaimMasterWhenItCannotHoldTheVIP(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*gateonv1.HaConfig)
	}{
		{"no interface", func(c *gateonv1.HaConfig) { c.Interface = "" }},
		{"invalid interface name", func(c *gateonv1.HaConfig) { c.Interface = "eth0; rm -rf /" }},
		{"unparseable virtual IP", func(c *gateonv1.HaConfig) { c.VirtualIps = []string{"not-an-ip"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodConfig()
			tc.mut(cfg)
			m := manager(t, cfg)

			m.step(context.Background())

			if m.active {
				t.Errorf("the node took MASTER with a config it cannot act on (%s).\n"+
					"It holds no VIP, but it advertises, and every peer that sees an "+
					"advert it does not outrank stays BACKUP. The address ends up "+
					"owned by nobody while the cluster reports itself healthy.",
					tc.name)
			}
		})
	}
}

// TestYieldingClearsMasterState is the second defect, and the one that makes the
// first unrecoverable.
//
// releaseVIPs sets active = false as its last statement, after two early
// returns. A node that yields with an interface it cannot act on keeps
// active == true: it goes on advertising as MASTER alongside the peer it just
// yielded to, and because step only acquires when !active, it can never take the
// VIP again either.
func TestYieldingClearsMasterState(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*gateonv1.HaConfig)
	}{
		{"valid config", func(*gateonv1.HaConfig) {}},
		{"invalid interface name", func(c *gateonv1.HaConfig) { c.Interface = "eth0; rm -rf /" }},
		{"no interface", func(c *gateonv1.HaConfig) { c.Interface = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodConfig()
			tc.mut(cfg)
			m := manager(t, cfg)
			m.active = true

			m.releaseVIPs()

			if m.active {
				t.Errorf("after yielding, the node still considers itself MASTER (%s).\n"+
					"It keeps advertising against the peer it yielded to, and step "+
					"only acquires when !active, so it can never take the VIP back "+
					"either. Yielding is a decision; it has to take effect whether or "+
					"not the ip command could run.", tc.name)
			}
		})
	}
}

// TestNodeTakesOverWhenNoMasterIsPresent is the control.
//
// Refusing a broken config must not become refusing to fail over.
func TestNodeTakesOverWhenNoMasterIsPresent(t *testing.T) {
	m := manager(t, goodConfig())

	m.step(context.Background())

	if !m.active {
		t.Error("a correctly configured node with no master in sight did not take " +
			"over; the checks above would then be preventing failover rather than " +
			"preventing a false one")
	}
}

// TestNodeDoesNotTakeOverWhileAMasterIsAlive covers the wait.
func TestNodeDoesNotTakeOverWhileAMasterIsAlive(t *testing.T) {
	m := manager(t, goodConfig())
	m.lastSeen = time.Now()

	m.step(context.Background())

	if m.active {
		t.Error("the node took over while a master was advertising within the " +
			"down interval; two nodes would hold the address")
	}
}

// TestMasterDownIntervalIsThreeAdvertisements pins the timing.
func TestMasterDownIntervalIsThreeAdvertisements(t *testing.T) {
	cfg := goodConfig()
	cfg.AdvertInt = 2

	// Just inside the interval: still BACKUP.
	m := manager(t, cfg)
	m.lastSeen = time.Now().Add(-5 * time.Second)
	m.step(context.Background())
	if m.active {
		t.Error("took over after 5s with a 2s advert interval; the master-down " +
			"interval is three intervals, and taking over early is a split brain " +
			"on a slow network")
	}

	// Past it: take over.
	m = manager(t, cfg)
	m.lastSeen = time.Now().Add(-7 * time.Second)
	m.step(context.Background())
	if !m.active {
		t.Error("did not take over after 7s with a 2s advert interval; the master " +
			"is gone and the address is unowned")
	}
}

// TestOneBadVIPDoesNotLoseTheOthers records where the line sits.
//
// The fix above refuses MASTER when the node can hold nothing. It must not
// refuse when the node can hold something: turning a typo in one of several
// addresses into a total loss of the service would be a worse failure than the
// one being fixed.
func TestOneBadVIPDoesNotLoseTheOthers(t *testing.T) {
	cfg := goodConfig()
	cfg.VirtualIps = []string{"not-an-ip", "192.0.2.10/24"}
	m := manager(t, cfg)

	m.step(context.Background())

	if !m.active {
		t.Error("one malformed address in the list stopped the node taking over at " +
			"all. The other address is well-formed and serviceable; refusing " +
			"everything makes a one-line config mistake an outage.")
	}
}

// TestNodeStaysBackupWhenTheAddressCommandFails covers the case CI found by
// accident.
//
// Validation passing is not the same as the address being taken. An
// unprivileged process, a missing interface, an address already held elsewhere
// -- each leaves `ip` returning non-zero with a configuration that looked
// entirely reasonable. A node in that position must not advertise, for the same
// reason a misconfigured one must not: an active node suppresses every peer that
// does not outrank it, so claiming MASTER without the address takes the service
// down rather than just failing locally.
func TestNodeStaysBackupWhenTheAddressCommandFails(t *testing.T) {
	m := failingManager(t, goodConfig())

	m.step(context.Background())

	if m.active {
		t.Error("the node took MASTER after every `ip addr add` failed. The config " +
			"validates, so nothing earlier catches it; the address is simply not " +
			"there. Advertising now silences the peer that could have taken it.")
	}
}

// TestYieldingClearsMasterStateWhenTheCommandFails is the same asymmetry on the
// way out.
//
// Releasing has to take effect even when the command does not, or a node that
// cannot run `ip` keeps advertising against the peer it just yielded to and can
// never re-acquire either.
func TestYieldingClearsMasterStateWhenTheCommandFails(t *testing.T) {
	m := failingManager(t, goodConfig())
	m.active = true

	m.releaseVIPs()

	if m.active {
		t.Error("a node whose `ip addr del` failed still considers itself MASTER; " +
			"yielding is a decision, not a consequence of the command exiting zero")
	}
}

// TestElectionOnlyNodeCanStillBecomeMaster marks where the refusal stops.
//
// A node with no virtual IPs configured holds nothing, but it is not claiming to
// hold anything either -- the check above is about a node that was given
// addresses and failed to take them. Refusing here as well looked tidy and broke
// something real: the documented two-node verification runs both managers with
// no VIPs precisely to isolate the election from `ip addr add`, greps their
// HA_VERDICT lines, and would have found two BACKUPs and no master forever.
//
// It is opt-in and Linux-only, so CI would never have said so.
func TestElectionOnlyNodeCanStillBecomeMaster(t *testing.T) {
	cfg := goodConfig()
	cfg.VirtualIps = nil
	m := manager(t, cfg)

	m.step(context.Background())

	if !m.active {
		t.Error("a node with no VIPs configured refused to become master. It has " +
			"nothing to acquire, so there is nothing it can be failing to hold; " +
			"refusing here breaks the two-node election check, which runs exactly " +
			"this configuration on purpose.")
	}
}
