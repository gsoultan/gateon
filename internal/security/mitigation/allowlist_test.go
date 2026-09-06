// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mitigation

import (
	"net/netip"
	"sync"
	"testing"
)

// The allowlist is exercised end-to-end from internal/middleware, which proves
// the enforcement sites consult it. These cover the package's own API: the
// parsing, the matching, and the two properties a security exemption has to
// have — off by default, and closed rather than open when it cannot tell.

func withList(t *testing.T, raw string) {
	t.Helper()
	SetAllowlist(ParseAllowlist(raw))
	t.Cleanup(func() { SetAllowlist(nil) })
}

// TestIsAllowlistedMatching covers the address handling.
//
// The v4-mapped form matters: a client arriving over a dual-stack listener can
// present either spelling of the same host, and failing to unmap would exempt it
// on one listener and refuse it on the other.
func TestIsAllowlistedMatching(t *testing.T) {
	withList(t, "203.0.113.0/24, 198.51.100.7, 2001:db8::/32")

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"203.0.113.255", true},
		{"198.51.100.7", true},  // bare address, pinned to /32 by ParseAllowlist
		{"198.51.100.8", false}, // its neighbour is not
		{"2001:db8::1", true},
		{"::ffff:203.0.113.1", true}, // the same host, v4-mapped
		{"203.0.114.1", false},
		{"2001:db9::1", false},
	} {
		if got := IsAllowlisted(tc.ip); got != tc.want {
			t.Errorf("IsAllowlisted(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestIsAllowlistedWithholdsOnBadInput pins the direction of the failure.
//
// An address that cannot be parsed has not been shown to be allowlisted, and the
// safe direction for a security exemption is to withhold it. The alternative —
// treating "I could not tell" as "exempt" — turns a malformed forwarding header
// into a bypass.
func TestIsAllowlistedWithholdsOnBadInput(t *testing.T) {
	withList(t, "0.0.0.0/0") // matches every address that parses

	for _, ip := range []string{"", "not-an-address", "203.0.113", "::ffff:zz"} {
		if IsAllowlisted(ip) {
			t.Errorf("IsAllowlisted(%q) exempted an address it could not parse", ip)
		}
	}
	// The control: a real address against the same list is exempt, so the cases
	// above fail for the reason claimed rather than because the list is empty.
	if !IsAllowlisted("203.0.113.1") {
		t.Fatal("the 0.0.0.0/0 list did not match a valid address; setup is wrong")
	}
}

// TestAllowlistIsOffUntilConfigured guards the default.
//
// An allowlist that matched anything before being configured would be a
// gateway-wide bypass installed by upgrading.
func TestAllowlistIsOffUntilConfigured(t *testing.T) {
	SetAllowlist(nil)
	for _, ip := range []string{"203.0.113.1", "10.0.0.1", "2001:db8::1", "127.0.0.1"} {
		if IsAllowlisted(ip) {
			t.Errorf("%s was exempt with nothing configured", ip)
		}
	}
	if n := AllowlistSize(); n != 0 {
		t.Errorf("AllowlistSize() = %d with nothing configured, want 0", n)
	}
}

// TestSetAllowlistClearsAndCounts covers the setter's two other jobs.
func TestSetAllowlistClearsAndCounts(t *testing.T) {
	SetAllowlist(ParseAllowlist("203.0.113.0/24, 198.51.100.0/24"))
	if n := AllowlistSize(); n != 2 {
		t.Errorf("AllowlistSize() = %d, want 2", n)
	}

	// An empty slice clears rather than installing a list that matches nothing,
	// so a reload that drops the setting turns the exemption off.
	SetAllowlist([]netip.Prefix{})
	if n := AllowlistSize(); n != 0 {
		t.Errorf("AllowlistSize() = %d after clearing, want 0", n)
	}
	if IsAllowlisted("203.0.113.1") {
		t.Error("an address stayed exempt after the list was cleared")
	}
}

// TestSetAllowlistCopiesItsInput stops a caller mutating live policy.
//
// The slice comes from configuration the caller still owns. Retaining it would
// let a later append or reslice change which sources are exempt on a running
// gateway, with nothing in the reload path to show for it.
func TestSetAllowlistCopiesItsInput(t *testing.T) {
	prefixes := ParseAllowlist("203.0.113.0/24")
	SetAllowlist(prefixes)
	t.Cleanup(func() { SetAllowlist(nil) })

	// Mutate the caller's slice in place.
	prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")

	if !IsAllowlisted("203.0.113.1") {
		t.Error("mutating the caller's slice changed the installed allowlist")
	}
	if IsAllowlisted("198.51.100.1") {
		t.Error("mutating the caller's slice added a source to the installed allowlist")
	}
}

// TestParseAllowlist covers the input shapes an operator actually writes.
func TestParseAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int
	}{
		{"empty", "", 0},
		{"whitespace only", "  ,  , ", 0},
		{"single cidr", "203.0.113.0/24", 1},
		{"bare address", "198.51.100.7", 1},
		{"mixed with spaces", " 203.0.113.0/24 , 198.51.100.7 ", 2},
		{"ipv6", "2001:db8::/32", 1},
		{"garbage is dropped", "203.0.113.0/24, not-an-address, /24", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(ParseAllowlist(tc.raw)); got != tc.want {
				t.Errorf("ParseAllowlist(%q) gave %d prefixes, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

// TestAllowlistIsSafeForConcurrentUse pins the reason it is an atomic pointer.
//
// It is read on the request path by several middlewares and written on config
// reload. The race detector is what actually proves this; the test exists to
// give it something to observe.
func TestAllowlistIsSafeForConcurrentUse(t *testing.T) {
	t.Cleanup(func() { SetAllowlist(nil) })

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				_ = IsAllowlisted("203.0.113.1")
				_ = AllowlistSize()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			if i%2 == 0 {
				SetAllowlist(ParseAllowlist("203.0.113.0/24"))
			} else {
				SetAllowlist(nil)
			}
		}
	}()
	wg.Wait()
}
