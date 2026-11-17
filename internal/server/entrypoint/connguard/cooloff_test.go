// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package connguard

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestACoolOffRefusesUntilItPasses(t *testing.T) {
	c := NewCoolOff(10*time.Second, 8)
	a := netip.MustParseAddr("10.0.0.1")
	now := time.Unix(1000, 0)
	c.Start(a, now)
	if !c.Refuses(a, now.Add(9*time.Second)) {
		t.Fatal("refused nothing inside the cool-off")
	}
	if c.Refuses(netip.MustParseAddr("10.0.0.2"), now) {
		t.Fatal("refused an address that was never cooled off")
	}
	if c.Refuses(a, now.Add(10*time.Second)) || c.Len() != 0 {
		t.Fatalf("still refusing, or still tracking %d addresses, after the cool-off", c.Len())
	}
}

// An attacker with more addresses than the bound cannot grow the map: the
// addresses past it are simply not cooled off.
func TestACoolOffIsBounded(t *testing.T) {
	c := NewCoolOff(10*time.Second, 2)
	now := time.Unix(1000, 0)
	for _, s := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		c.Start(netip.MustParseAddr(s), now)
	}
	if c.Len() != 2 || c.Refuses(netip.MustParseAddr("10.0.0.3"), now) {
		t.Fatalf("tracking %d addresses, want the bound of 2 with the third left out", c.Len())
	}
	// Once the earlier ones expire there is room again.
	later := now.Add(11 * time.Second)
	c.Start(netip.MustParseAddr("10.0.0.3"), later)
	if !c.Refuses(netip.MustParseAddr("10.0.0.3"), later) || c.Len() != 1 {
		t.Fatalf("after expiry: tracking %d, want only the new address", c.Len())
	}
}

func TestANilCoolOffRefusesNothing(t *testing.T) {
	var c *CoolOff
	a := netip.MustParseAddr("10.0.0.1")
	c.Start(a, time.Now())
	if c.Refuses(a, time.Now()) || NewCoolOff(0, 8) != nil {
		t.Fatal("a nil or zero-length cool-off refused a connection")
	}
}

func TestTheCalmCloseLineNamesItsPeer(t *testing.T) {
	for line, want := range map[string]string{
		"http2: server connection error from 10.99.0.22:58107: connection error: ENHANCE_YOUR_CALM\n":  "10.99.0.22",
		"http2: server connection error from [2001:db8::1]:443: connection error: ENHANCE_YOUR_CALM\n": "2001:db8::1",
		"http2: server connection error from 10.0.0.1:1: connection error: PROTOCOL_ERROR\n":           "",
		"http: TLS handshake error from 10.0.0.1:1: EOF\n":                                             "",
		"http2: server connection error from not-an-addr: connection error: ENHANCE_YOUR_CALM\n":       "",
	} {
		got, ok := calmPeer([]byte(line))
		if got != want || ok != (want != "") {
			t.Errorf("calmPeer(%q) = %q, %v; want %q", line, got, ok, want)
		}
	}
}

func TestTheWatcherPassesEveryLineOn(t *testing.T) {
	c := NewCoolOff(time.Minute, 8)
	var out bytes.Buffer
	w := c.WatchServerErrors(&out, func(ip string) (netip.Addr, bool) { a, err := netip.ParseAddr(ip); return a, err == nil })
	line := "http2: server connection error from 10.0.0.9:7: connection error: ENHANCE_YOUR_CALM\n"
	if _, err := w.Write([]byte(line)); err != nil || out.String() != line {
		t.Fatalf("wrote %q, %v; want the line passed on", out.String(), err)
	}
	if !c.Refuses(netip.MustParseAddr("10.0.0.9"), time.Now()) {
		t.Fatal("the closed peer is not cooling off")
	}
}
