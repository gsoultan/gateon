// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"net"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// On a virtualized NIC the TC program is the one filtering: the ENA driver
// refuses native XDP at the EC2 defaults, so there every drop decision is
// tc_gateon_ingress's. These hold it to the verdicts the XDP tests hold
// xdp_gateon_main to.

// mgmtAllowlistConfig turns the kernel management allowlist on with one address
// in it, through the same fields the dashboard writes.
func mgmtAllowlistConfig() *gateonv1.EbpfConfig {
	return &gateonv1.EbpfConfig{
		Enabled:             true,
		XdpIpShunning:       true,
		EnableMgmtWhitelist: true,
		MgmtWhitelistIps:    []string{"198.51.100.40"},
		MgmtPort:            8443,
	}
}

// TestTCManagementAllowlistDropsUnlistedSources is the defect. TC's allowlist
// branch let listed sources through early and had no arm that dropped anyone:
// the program never read the destination port. So on TC the setting admitted
// every address, while the dashboard said an unlisted one could not reach the
// management port at all.
func TestTCManagementAllowlistDropsUnlistedSources(t *testing.T) {
	m, coll := loadedManager(t, mgmtAllowlistConfig())
	tc := coll.Programs[tcProgName]
	admin, stranger := net.IPv4(198, 51, 100, 40), net.IPv4(203, 0, 113, 50)

	if v := verdict(t, tc, ipv4TCP(admin, 8443, tcpSYN), 1); v != tcActOK {
		t.Fatalf("the listed address cannot reach the management port (verdict %d, want TC_ACT_OK %d)", v, tcActOK)
	}
	if v := verdict(t, tc, ipv4TCP(stranger, 8443, tcpSYN), 1); v != tcActShot {
		t.Errorf("an unlisted address reached the management port through TC (verdict %d, want "+
			"TC_ACT_SHOT %d): enable_mgmt_whitelist enforces nothing on this hook", v, tcActShot)
	}
	if n := dropped(t, m, "invalid_port_knock"); n != 1 {
		t.Errorf("invalid_port_knock drop counter = %d, want 1: the drop, if any, was not the allowlist", n)
	}
	if v := verdict(t, tc, ipv4TCP(stranger, 443, tcpSYN), 1); v != tcActOK {
		t.Errorf("the allowlist dropped an unlisted address on port 443 (verdict %d, want TC_ACT_OK %d): "+
			"it guards the management port, not the gateway", v, tcActOK)
	}
}

// TestTCRateLimitOnAllowsABurstThenDrops: with the limiter on, a window-sized
// burst passes and a sustained flood does not -- on the hook EC2 actually runs.
func TestTCRateLimitOnAllowsABurstThenDrops(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpRateLimit: true})
	tc := coll.Programs[tcProgName]
	pkt := ipv4TCP(net.IPv4(198, 51, 100, 22), 443, tcpACK)

	if v := verdict(t, tc, pkt, 64); v != tcActOK {
		t.Fatalf("the 64th packet of a client's first burst got verdict %d, want TC_ACT_OK %d: "+
			"a limiter with no burst allowance drops the second segment of every window", v, tcActOK)
	}
	if v := verdict(t, tc, pkt, 4096); v != tcActShot {
		t.Fatalf("4096 further packets in well under a millisecond were all passed by TC (last verdict %d); "+
			"the limiter is not enforcing on this hook", v)
	}
	if n := dropped(t, m, "rate_limited"); n == 0 {
		t.Error("TC dropped packets but the rate_limited counter did not move")
	}
}
