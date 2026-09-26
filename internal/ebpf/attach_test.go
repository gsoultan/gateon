// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// errEINVAL stands in for the driver's rejection of a native attach, which is
// what cilium/ebpf surfaces as "create link: invalid argument".
var errEINVAL = errors.New("create link: invalid argument")

// ec2Jumbo is a default EC2 instance: ENA driver, VPC MTU of 9001, and the
// driver using every queue the instance has. Both native-XDP blockers at once.
func ec2Jumbo() nicFacts {
	return nicFacts{Name: "ens5", Driver: "ena", MTU: 9001, RXQueues: 8, NumCPU: 8, PageSize: 4096}
}

// TestGenericXDPRequiresOptIn is the regression guard for the actual defect:
// the loader used to degrade to generic/SKB mode on its own, which taxes every
// packet without dropping any earlier. Silence is not consent.
func TestGenericXDPRequiresOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *gateonv1.EbpfConfig
		want bool
	}{
		{"nil config", nil, false},
		{"zero config", &gateonv1.EbpfConfig{}, false},
		{"feature enabled but no opt-in", &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true}, false},
		{"explicit opt-in", &gateonv1.EbpfConfig{AllowGenericXdp: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowGenericXDP(tc.cfg); got != tc.want {
				t.Fatalf("allowGenericXDP() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNativeXDPMaxMTU(t *testing.T) {
	// The ENA driver's own arithmetic on a 4 KiB page: 4096 - 22 - 256 - 320.
	if got, want := nativeXDPMaxMTU(4096), 3498; got != want {
		t.Errorf("nativeXDPMaxMTU(4096) = %d, want %d", got, want)
	}
	// A 16 KiB-page kernel is far more permissive, which is why the limit is
	// derived from the page size rather than hardcoded to 3498.
	if got := nativeXDPMaxMTU(16384); got <= 9001 {
		t.Errorf("nativeXDPMaxMTU(16384) = %d, want room for a 9001-byte MTU", got)
	}
}

func TestDiagnoseJumboMTUNamesTheLimitAndTheFix(t *testing.T) {
	d := diagnoseNativeXDP(ec2Jumbo(), false, errEINVAL)

	for _, want := range []string{"ens5", "ena", "9001", "3498"} {
		if !strings.Contains(d.Summary, want) {
			t.Errorf("summary %q missing %q", d.Summary, want)
		}
	}
	if !hasRemedyContaining(d.Remedies, "ip link set dev ens5 mtu 3498") {
		t.Errorf("remedies %q missing the MTU command", d.Remedies)
	}
}

func TestDiagnoseQueueSaturationSuggestsHalvingChannels(t *testing.T) {
	d := diagnoseNativeXDP(ec2Jumbo(), false, errEINVAL)

	if !strings.Contains(d.Summary, "8 RX queues on 8 CPUs") {
		t.Errorf("summary %q does not report the queue saturation", d.Summary)
	}
	if !hasRemedyContaining(d.Remedies, "ethtool -L ens5 combined 4") {
		t.Errorf("remedies %q missing the ethtool command", d.Remedies)
	}
}

// A NIC with headroom on both axes must not be blamed for either — otherwise the
// diagnosis invents causes and sends the operator after the wrong knob.
func TestDiagnoseWithoutBlockersRelaysTheDriverError(t *testing.T) {
	f := nicFacts{Name: "eth0", Driver: "virtio_net", MTU: 1500, RXQueues: 2, NumCPU: 8, PageSize: 4096}
	d := diagnoseNativeXDP(f, false, errEINVAL)

	if !strings.Contains(d.Summary, errEINVAL.Error()) {
		t.Errorf("summary %q should relay the driver error when no cause is known", d.Summary)
	}
	for _, unwanted := range []string{"MTU 1500", "RX queues"} {
		if strings.Contains(d.Summary, unwanted) {
			t.Errorf("summary %q invented a cause: %q", d.Summary, unwanted)
		}
	}
}

// Unknown facts must degrade to "I don't know", never to a fabricated number.
func TestDiagnoseToleratesUnknownFacts(t *testing.T) {
	d := diagnoseNativeXDP(nicFacts{Name: "ens5"}, false, errEINVAL)

	if !strings.Contains(d.Summary, errEINVAL.Error()) {
		t.Errorf("summary %q should relay the driver error with no facts", d.Summary)
	}
	if strings.Contains(d.Summary, "MTU 0") || strings.Contains(d.Summary, "0 RX queues") {
		t.Errorf("summary %q leaked an unknown-value zero", d.Summary)
	}
}

// TC is the real answer on a virtualized NIC, so every failed native attach has
// to point at it. Start falls back to it on its own unless generic mode was
// opted into, so that opt-in is what the advice has to name.
func TestDiagnoseAlwaysOffersTheTCAlternative(t *testing.T) {
	for _, allowGeneric := range []bool{false, true} {
		d := diagnoseNativeXDP(ec2Jumbo(), allowGeneric, errEINVAL)
		if !hasRemedyContaining(d.Remedies, "TC ingress hook") {
			t.Errorf("allowGeneric=%v: remedies %q never mention the TC ingress hook", allowGeneric, d.Remedies)
		}
	}
	d := diagnoseNativeXDP(ec2Jumbo(), true, errEINVAL)
	if !hasRemedyContaining(d.Remedies, "unset ebpf.allow_generic_xdp") {
		t.Errorf("with generic mode opted into, remedies %q do not say that unsetting it is what "+
			"brings the TC fallback back", d.Remedies)
	}
}

// TestTryTCFallsBackWheneverXDPWasWantedAndDidNotAttach: at the EC2 defaults
// native XDP is refused, and Start used to attach nothing unless tc_filtering
// happened to be set. An XDP feature being on is the request to filter; the TC
// hook is where that can happen.
func TestTryTCFallsBackWheneverXDPWasWantedAndDidNotAttach(t *testing.T) {
	cases := []struct {
		name        string
		cfg         *gateonv1.EbpfConfig
		xdpAttached bool
		want        bool
	}{
		{"XDP wanted, refused, tc_filtering off", &gateonv1.EbpfConfig{XdpIpShunning: true}, false, true},
		{"XDP wanted, refused, tc_filtering on", &gateonv1.EbpfConfig{XdpRateLimit: true, TcFiltering: true}, false, true},
		{"XDP attached: never both hooks", &gateonv1.EbpfConfig{XdpIpShunning: true, TcFiltering: true}, true, false},
		{"only tc_filtering", &gateonv1.EbpfConfig{TcFiltering: true}, false, true},
		{"nothing asked for", &gateonv1.EbpfConfig{}, false, false},
		{"no config", nil, false, false},
	}
	for _, c := range cases {
		if got := tryTC(c.cfg, c.xdpAttached); got != c.want {
			t.Errorf("%s: tryTC = %v, want %v", c.name, got, c.want)
		}
	}
}

// Tables in /proc/net/route's own format, trailing whitespace and all.
const (
	routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	// An EC2 host: default route and subnet on ens5.
	routesEC2 = routeHeader +
		"ens5\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"ens5\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	// A Docker host: docker0's subnet is listed before the default route.
	routesDockerHost = routeHeader +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"ens5\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)

func TestDefaultRouteInterface(t *testing.T) {
	cases := []struct {
		name, table, want string
	}{
		{"EC2 host", routesEC2, "ens5"},
		{"a subnet route listed first is not the default", routesDockerHost, "ens5"},
		{"container", routeHeader + "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n", "eth0"},
		{"lowest metric wins, whatever the order", routeHeader +
			"ens6\t00000000\t0103000A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
			"ens5\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", "ens5"},
		{"a default route that is not up is skipped", routeHeader +
			"ens5\t00000000\t0102000A\t0002\t0\t0\t100\t00000000\t0\t0\t0\n", ""},
		{"no default route", routeHeader + "ens5\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", ""},
		{"header only", routeHeader, ""},
		{"unreadable", "", ""},
	}
	for _, c := range cases {
		if got := defaultRouteInterface(c.table); got != c.want {
			t.Errorf("%s: defaultRouteInterface = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTargetInterfacePrefersConfigThenTheDefaultRoute: eth0 used to be the
// whole rule, and no interface on a current EC2 host has that name, so an
// unconfigured install there failed to attach with "no such network interface".
func TestTargetInterfacePrefersConfigThenTheDefaultRoute(t *testing.T) {
	if got := targetInterface("", defaultRouteInterface(routesEC2)); got != "ens5" {
		t.Errorf("unconfigured on an EC2 host: got %q, want the default-route interface ens5", got)
	}
	if got := targetInterface("ens6", "ens5"); got != "ens6" {
		t.Errorf("configured: got %q, want the configured ens6", got)
	}
	if got := targetInterface("", ""); got != "eth0" {
		t.Errorf("no configuration and no default route: got %q, want eth0", got)
	}
}

func TestDiagnoseWordingDistinguishesRefusalFromFallback(t *testing.T) {
	refused := diagnoseNativeXDP(ec2Jumbo(), false, errEINVAL)
	if !strings.Contains(refused.Summary, "refusing generic") {
		t.Errorf("summary %q should say the attach was refused", refused.Summary)
	}
	if !strings.Contains(refused.Summary, "allow_generic_xdp") {
		t.Errorf("summary %q should name the override knob", refused.Summary)
	}

	fellBack := diagnoseNativeXDP(ec2Jumbo(), true, errEINVAL)
	if strings.Contains(fellBack.Summary, "refusing generic") {
		t.Errorf("summary %q claims refusal after opting in", fellBack.Summary)
	}
	if !strings.Contains(fellBack.Summary, "every packet") {
		t.Errorf("summary %q should still state the per-packet cost", fellBack.Summary)
	}
}

func hasRemedyContaining(remedies []string, want string) bool {
	for _, r := range remedies {
		if strings.Contains(r, want) {
			return true
		}
	}
	return false
}

// Falling back to TC narrows what is enforced. Whatever else changes, that
// narrowing must stay visible — a silent gap here is a security hole, since an
// operator would go on believing a feature was in force when nothing enforced it.
func TestTCUnsupportedNamesTheGaps(t *testing.T) {
	if gaps := tcUnsupported(nil); gaps != nil {
		t.Errorf("tcUnsupported(nil) = %v, want nil", gaps)
	}

	// Features the TC hook does implement must not be reported as gaps.
	tcCapable := &gateonv1.EbpfConfig{
		Enabled: true, XdpIpShunning: true, XdpRateLimit: true,
	}
	if gaps := tcUnsupported(tcCapable); len(gaps) != 0 {
		t.Errorf("tcUnsupported(shun/rate-limit) = %v, want none", gaps)
	}

	full := &gateonv1.EbpfConfig{
		EnableKnocking: true,
		AfXdpPhantom:   true, XdpLoadBalancing: true,
	}
	want := []string{"enable_knocking", "af_xdp_phantom", "xdp_load_balancing"}
	gaps := tcUnsupported(full)
	if len(gaps) != len(want) {
		t.Fatalf("tcUnsupported() = %v, want %v", gaps, want)
	}
	for i, w := range want {
		if gaps[i] != w {
			t.Errorf("gap %d = %q, want %q", i, gaps[i], w)
		}
	}
}
