// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// Honeypot bans and strikes were keyed by the exact client address. An IPv6
// customer is delegated a /64 -- 2^64 addresses it can source from at no cost --
// so rotating through them, a scanner was never refused for longer than the one
// request that tripped each ban, never climbed the ladder, and after ten thousand
// trap hits had filled both maps to their cap. At the cap the blocklist refuses
// to grow, so the next scanner to hit a trap -- anyone, on any address -- was not
// banned at all until entries expired, and the rotating customer could keep it
// that way.
//
// Root cause in one sentence: the ban was keyed on a unit the client chooses
// freely (an IPv6 address) rather than the unit it is delegated (the /64).

// TestOneIPv6CustomerCannotSwitchTheHoneypotOff is the regression test.
func TestOneIPv6CustomerCannotSwitchTheHoneypotOff(t *testing.T) {
	resetHoneypotState(t)
	now := time.Now()

	// Ten thousand trap hits from one /64, recorded exactly as the middleware
	// records one (the logging it also does is left out: it is 10,000 lines).
	for i := range maxHoneypotBlocklist {
		addr := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		blockHoneypotIP(addr, now.Add(honeypotBanFor(addr, now)))
	}

	const scanner = "203.0.113.250"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Honeypot(HoneypotConfig{Paths: defaultHoneypotPaths()})(ok)
	serve := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = scanner + ":52000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := serve("/.env"); got != http.StatusForbidden {
		t.Fatalf("setup: the trap itself answered %d", got)
	}
	if got := serve("/"); got != http.StatusForbidden {
		t.Fatalf("a scanner that hit a trap is not banned (got %d): one IPv6 customer "+
			"rotating inside its own /64 filled the ban list and switched bans off for everyone", got)
	}
}

// TestAnIPv6BanCoversItsSlash64 pins what one ban now reaches, through both
// honeypots: every address of the offender's /64, and nothing outside it.
func TestAnIPv6BanCoversItsSlash64(t *testing.T) {
	for name, h := range bothHoneypots(t) {
		t.Run(name, func(t *testing.T) {
			resetHoneypotState(t)
			if got := honeypotAnswer6(h, "2001:db8:1:2::10", "/.env"); got != http.StatusForbidden {
				t.Fatalf("setup: the trap answered %d", got)
			}
			if got := honeypotAnswer6(h, "2001:db8:1:2:ffff::99", "/"); got != http.StatusForbidden {
				t.Errorf("another address in the offender's /64 got %d: rotating inside the "+
					"/64 still sheds the ban", got)
			}
			if got := honeypotAnswer6(h, "2001:db8:1:3::10", "/"); got != http.StatusOK {
				t.Errorf("an address in the neighbouring /64 got %d: the ban reaches past "+
					"the network that earned it", got)
			}
		})
	}
}

// TestIPv6StrikesAccumulateAcrossTheSlash64 pins the ladder half: hits from
// three addresses of one /64 are three strikes, not three first offences.
func TestIPv6StrikesAccumulateAcrossTheSlash64(t *testing.T) {
	resetHoneypotState(t)
	now := time.Now()
	for i, addr := range []string{"2001:db8:9:9::1", "2001:db8:9:9::2", "2001:db8:9:9:1:2:3:4"} {
		if got, want := honeypotBanFor(addr, now), honeypotBanLadder[i]; got != want {
			t.Errorf("hit %d (from %s) banned for %s, want %s: a client rotating inside "+
				"its /64 starts every hit at the bottom of the ladder", i+1, addr, got, want)
		}
	}
}

// TestIPv4BansStayPerAddress is the other side of the rule: IPv4 keeps the
// per-address ban it always had, and a v4-mapped address is banned as the IPv4
// host it is, whichever spelling the ban was recorded under.
func TestIPv4BansStayPerAddress(t *testing.T) {
	resetHoneypotState(t)
	until := time.Now().Add(time.Hour)

	blockHoneypotIP("::ffff:203.0.113.5", until)
	if !honeypotBanActive("203.0.113.5") {
		t.Error("a ban recorded under the v4-mapped spelling does not refuse the IPv4 spelling")
	}
	blockHoneypotIP("198.51.100.5", until)
	if !honeypotBanActive("::ffff:198.51.100.5") {
		t.Error("a ban recorded under the IPv4 spelling does not refuse the v4-mapped spelling")
	}
	if honeypotBanActive("203.0.113.6") {
		t.Error("an IPv4 ban reached the next address: IPv4 bans are per address")
	}
}

// TestReleasingOneAddressLiftsItsSlash64 pins the operator's release to the
// ban's key. RemoveMitigatedThreat hands over the one address it has, and the
// ban is filed under that address's /64; deleting the address itself found
// nothing and left the /64 refused while the dashboard reported success.
func TestReleasingOneAddressLiftsItsSlash64(t *testing.T) {
	resetHoneypotState(t)
	now := time.Now()
	const offender, released = "2001:db8:7:7::10", "2001:db8:7:7::77"

	for range 3 {
		blockHoneypotIP(offender, now.Add(honeypotBanFor(offender, now)))
	}
	if !ReleaseHoneypotBan(released) {
		t.Error("releasing an address of the banned /64 reported no ban to lift")
	}
	if honeypotBanActive(offender) || honeypotBanActive(released) {
		t.Fatal("the /64 is still banned after one of its addresses was released")
	}
	if got := honeypotBanFor(offender, now); got != honeypotBanLadder[0] {
		t.Errorf("the next hit after the release was banned for %s, want %s: the release "+
			"left the /64's strikes behind", got, honeypotBanLadder[0])
	}
}

// TestAnAllowlistedAddressIsNotRefusedByItsNetworksBan: an allowlisted address
// is never banned itself, but a /64 ban covers it, so the ban check has to ask
// the allowlist too -- or a neighbour's trap hit refuses the operator's own
// scanner, which is what GATEON_MITIGATION_ALLOWLIST promises will not happen.
func TestAnAllowlistedAddressIsNotRefusedByItsNetworksBan(t *testing.T) {
	resetHoneypotState(t)
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix("2001:db8:5:5::5/128")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	blockHoneypotIP("2001:db8:5:5::10", time.Now().Add(time.Hour))
	if !honeypotBanActive("2001:db8:5:5::11") {
		t.Fatal("setup: the /64 is not banned")
	}
	if honeypotBanActive("2001:db8:5:5::5") {
		t.Error("an allowlisted address is refused by its neighbour's ban")
	}
}

// honeypotAnswer6 sends a GET for path from an IPv6 address through h.
func honeypotAnswer6(h http.Handler, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "[" + ip + "]:42500"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}
