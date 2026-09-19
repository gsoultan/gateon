// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// These are the parts of the management-whitelist and load-balancer paths that
// need no kernel. The verdicts they lead to are checked against a real kernel in
// manager_whitelist_lb_linux_test.go.

// TestUpdateLoadBalancerBackendsRefusesBackendsItCannotAddress is the blackhole.
//
// The call takes IP addresses only, and nothing in the tree resolves a backend's
// MAC -- there is no ARP and no static MAC table. It used to accept the list
// anyway and write an all-zero destination MAC, which the XDP path then copied
// into eth->h_dest before returning XDP_TX: the redirected traffic went onto the
// wire addressed to 00:00:00:00:00:00, with the IPv4 and L4 checksums left
// stale, and XDP_TX has no fallback, so every one of those packets was gone.
// An operator who turned xdp_load_balancing on got a silent, total outage for
// the traffic they had just pointed at it.
//
// So the call has to refuse, and the error has to name the setting: this is the
// only place the operator finds out, and "load balancer maps not loaded" -- what
// it used to say off a live kernel -- sends them looking at the wrong thing.
func TestUpdateLoadBalancerBackendsRefusesBackendsItCannotAddress(t *testing.T) {
	m := NewEbpfManager(&gateonv1.EbpfConfig{Enabled: true, XdpLoadBalancing: true})

	err := m.UpdateLoadBalancerBackends([]string{"10.0.0.11", "10.0.0.12"})
	if err == nil {
		t.Fatal("installing two backends with no resolvable destination MAC was accepted.\n" +
			"The XDP path rewrites eth->h_dest to the stored MAC and returns XDP_TX, so an " +
			"all-zero MAC puts the redirected traffic on the wire addressed to nobody and it " +
			"is silently destroyed. This call must refuse, not accept and blackhole.")
	}
	if !strings.Contains(err.Error(), "xdp_load_balancing") {
		t.Errorf("the refusal does not name the setting that caused it: %q.\n"+
			"This error is the operator's only signal that the feature they enabled is not "+
			"going to work; it has to say which setting to turn off.", err)
	}
}

// TestUpdateLoadBalancerBackendsAcceptsAnEmptyList covers the other direction:
// clearing the backends is the safe state and must not be reported as a failure,
// or an operator turning the feature back off sees an error for doing the right
// thing.
func TestUpdateLoadBalancerBackendsAcceptsAnEmptyList(t *testing.T) {
	m := NewEbpfManager(&gateonv1.EbpfConfig{Enabled: true})

	if err := m.UpdateLoadBalancerBackends(nil); err != nil {
		t.Errorf("clearing the backend list returned %v; removing backends is the state this "+
			"feature is safe in and must always succeed", err)
	}
}

// TestXDPLoadBalancingUnimplementedTracksTheSetting pins the attach-time notice.
// Nothing in the tree calls UpdateLoadBalancerBackends yet, so without this an
// operator can enable xdp_load_balancing and get no message at all.
func TestXDPLoadBalancingUnimplementedTracksTheSetting(t *testing.T) {
	if xdpLoadBalancingUnimplemented(nil) {
		t.Error("a nil config reported xdp_load_balancing as enabled")
	}
	if xdpLoadBalancingUnimplemented(&gateonv1.EbpfConfig{Enabled: true}) {
		t.Error("a config with xdp_load_balancing unset reported it as enabled")
	}
	if !xdpLoadBalancingUnimplemented(&gateonv1.EbpfConfig{Enabled: true, XdpLoadBalancing: true}) {
		t.Error("xdp_load_balancing is on and the operator would be told nothing about it")
	}
}

// TestRevokedWhitelistKeysNamesOnlyWhatConfigDropped is the delta that decides
// which kernel entries get deleted. Naming one address too many revokes a live
// operator; naming one too few leaves a removed administrator with kernel-level
// access to the management port.
func TestRevokedWhitelistKeysNamesOnlyWhatConfigDropped(t *testing.T) {
	key := func(t *testing.T, ip string) uint32 {
		t.Helper()
		n, err := ipToUint32(ip)
		if err != nil {
			t.Fatalf("ipToUint32(%q): %v", ip, err)
		}
		return n
	}
	set := func(t *testing.T, ips ...string) map[uint32]struct{} {
		t.Helper()
		s := make(map[uint32]struct{}, len(ips))
		for _, ip := range ips {
			s[key(t, ip)] = struct{}{}
		}
		return s
	}

	for _, tc := range []struct {
		name string
		prev []string
		next []string
		want []string
	}{
		{"nothing installed yet", nil, []string{"10.0.0.1"}, nil},
		{"unchanged", []string{"10.0.0.1"}, []string{"10.0.0.1"}, nil},
		{"one removed", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1"}, []string{"10.0.0.2"}},
		{"all removed", []string{"10.0.0.1", "10.0.0.2"}, nil, []string{"10.0.0.1", "10.0.0.2"}},
		{"replaced", []string{"10.0.0.1"}, []string{"10.0.0.9"}, []string{"10.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := revokedWhitelistKeys(set(t, tc.prev...), set(t, tc.next...))
			var want []uint32
			for _, ip := range tc.want {
				want = append(want, key(t, ip))
			}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("revoked %v, want %v: this set is exactly what gets deleted from "+
					"mgmt_whitelist, so a wrong answer either strands a revoked administrator "+
					"or locks out a current one", got, want)
			}
		})
	}
}

// TestWhitelistKeysStopsAtTheKernelMapCapacity: mgmt_whitelist holds 1024
// entries, so tracking more would grow the Go-side set without anything in the
// kernel matching it, and every later update would issue deletes for keys that
// were never installed.
func TestWhitelistKeysStopsAtTheKernelMapCapacity(t *testing.T) {
	ips := make([]string, 0, mgmtWhitelistMax+100)
	for i := 0; i < mgmtWhitelistMax+100; i++ {
		ips = append(ips, fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}

	if got := len(whitelistKeys(ips)); got != mgmtWhitelistMax {
		t.Errorf("whitelistKeys kept %d of %d addresses, want %d: the set has to stay bounded "+
			"by the kernel map it mirrors", got, len(ips), mgmtWhitelistMax)
	}
}

// TestWhitelistKeysDropsWhatItCannotEncode: an address the map cannot be keyed
// by must not be tracked either, or the next update tries to delete a key that
// was never there.
func TestWhitelistKeysDropsWhatItCannotEncode(t *testing.T) {
	keys := whitelistKeys([]string{"10.0.0.1", "not-an-ip", "2001:db8::1", "10.0.0.1"})

	if len(keys) != 1 {
		t.Fatalf("whitelistKeys kept %d entries, want 1: only 10.0.0.1 is encodable, and it "+
			"appears twice", len(keys))
	}
	want, err := ipToUint32("10.0.0.1")
	if err != nil {
		t.Fatalf("ipToUint32: %v", err)
	}
	if _, ok := keys[want]; !ok {
		t.Error("the one usable address was not kept")
	}
}
