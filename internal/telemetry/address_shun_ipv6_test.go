// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
	"time"
)

// The automatic shun's evidence and the block list's enforcement were keyed
// per IPv6 address, while the kernel's shun map, the connection caps and the
// honeypot key an IPv6 client by its /64 (dataplane F5, ADR 0058). A host is
// delegated a /64 and picks its own low 64 bits, so one rotating through it
// put each attacking build on a fresh key and was never shunned, and a block
// of one of its addresses it left by choosing another.

// rotatingHost is one IPv6 host's /64, and its i-th address.
func rotatingHost(i int) string { return fmt.Sprintf("2001:db8:5:6::%x", 0x1000+i) }

func TestAHostRotatingThroughItsIPv6SlashSixtyFourIsShunned(t *testing.T) {
	shunTestStore(t)
	for i := range ipShunMinClasses {
		attackFrom(shunBuild(i), rotatingHost(i), time.Time{})
	}
	if !shunned(rotatingHost(0)) {
		t.Fatalf("%d attacking builds from one /64, each from an address of its own, did not shun it: "+
			"the evidence is kept per IPv6 address, which the host chooses", ipShunMinClasses)
	}
	for _, other := range []string{rotatingHost(99), "2001:db8:5:6:ffff:ffff:ffff:ffff"} {
		if !shunned(other) {
			t.Errorf("%s is in the shunned /64 and was served", other)
		}
	}
	if shunned("2001:db8:5:7::1") {
		t.Error("the neighbouring /64 was shunned with it")
	}
}

// IPv4 is unchanged: five builds from five addresses of one /24 are five
// addresses, none of them shunned.
func TestIPv4EvidenceIsStillKeptPerAddress(t *testing.T) {
	shunTestStore(t)
	for i := range ipShunMinClasses {
		attackFrom(shunBuild(i), fmt.Sprintf("198.51.100.%d", 10+i), time.Time{})
	}
	for i := range ipShunMinClasses {
		if ip := fmt.Sprintf("198.51.100.%d", 10+i); shunned(ip) {
			t.Fatalf("%s was shunned for its neighbours' evidence", ip)
		}
	}
}

// An operator's block of one IPv6 address blocks its /64 -- what the kernel
// already did with eBPF on -- and is released from any address in it. Read
// from the database as well as from the cache, on both engines.
func TestABlockOfAnIPv6AddressCoversItsSlashSixtyFour(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const blocked, sibling, outside = "2001:db8:7:8::5", "2001:db8:7:8:abcd::1", "2001:db8:7:9::5"
		if err := MarkIPMitigated(blocked, "test"); err != nil {
			t.Fatal(err)
		}
		for _, fromDB := range []bool{false, true} {
			if fromDB {
				purgeShunCache()
			}
			if !IsIPMitigated(sibling) {
				t.Errorf("fromDB=%v: %s shares the blocked /64 and was served", fromDB, sibling)
			}
			if IsIPMitigated(outside) {
				t.Errorf("fromDB=%v: %s is outside the blocked /64 and was refused", fromDB, outside)
			}
		}
		if err := MarkIPUnmitigated(sibling); err != nil {
			t.Fatal(err)
		}
		purgeShunCache()
		if IsIPMitigated(blocked) {
			t.Error("a release from another address of the /64 did not lift the block")
		}
	})
}

// A v4-mapped address is the IPv4 host it spells: one key for both.
func TestAVFourMappedAddressIsTheIPv4Address(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		if err := MarkIPMitigated("::ffff:198.51.100.40", "test"); err != nil {
			t.Fatal(err)
		}
		purgeShunCache()
		if !IsIPMitigated("198.51.100.40") {
			t.Error("a block of the v4-mapped spelling did not reach the IPv4 spelling")
		}
		if IsIPMitigated("198.51.100.41") {
			t.Error("the IPv4 neighbour was refused")
		}
	})
}

// The threat list shows whether each threat's source is shunned by joining
// the row keyed by its address; an IPv6 source is shunned under its /64's key,
// so a threat from another address of a shunned /64 is shown as shunned from
// the block list.
func TestAThreatFromAShunnedSlashSixtyFourIsListedAsShunned(t *testing.T) {
	shunTestStore(t)
	if err := MarkIPMitigated("2001:db8:a:b::1", "test"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"2001:db8:a:b::99", "2001:db8:a:c::99"} {
		RecordSecurityThreat(SecurityThreat{Type: "bot_detected", Category: "bot",
			ActionTaken: ActionDetected, SourceIP: ip, Time: time.Now()})
	}
	FlushThreats()
	seen := 0
	for _, th := range GetSecurityThreatsLite(t.Context(), 10, 0, nil) {
		switch th.SourceIP {
		case "2001:db8:a:b::99":
			seen++
			if !th.Mitigated {
				t.Error("a threat from a shunned /64 is listed as not shunned")
			}
		case "2001:db8:a:c::99":
			seen++
			if th.Mitigated {
				t.Error("a threat from the neighbouring /64 is listed as shunned")
			}
		}
	}
	if seen != 2 {
		t.Fatalf("listed %d of the 2 threats", seen)
	}
}
