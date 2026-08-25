// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"fmt"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Kernel constants that decide whether a driver can offer native XDP. They are
// spelled out here so the operator-facing diagnosis can quote real numbers
// instead of relaying the driver's bare EINVAL.
const (
	// xdpPacketHeadroom is XDP_PACKET_HEADROOM (include/net/xdp.h). Generic XDP
	// insists on this much headroom and calls pskb_expand_head() — a fresh
	// allocation plus a full packet copy — for every skb that arrives without it.
	xdpPacketHeadroom = 256
	// skbSharedInfoAligned is SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) on
	// 64-bit kernels: the tailroom every page-backed receive buffer reserves.
	skbSharedInfoAligned = 320
	// frameOverhead is ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN.
	frameOverhead = 14 + 4 + 4
)

// nativeXDPMaxMTU mirrors the ENA driver's ENA_XDP_MAX_MTU. A single page has to
// hold the frame, the XDP headroom and the skb_shared_info tailroom, so the
// usable MTU is whatever is left of a page — 3498 bytes on a 4 KiB-page x86_64
// host. It is derived from the running page size rather than hardcoded because
// the limit moves with it (a 16 KiB-page arm64 kernel is far more permissive).
//
// This is an estimate, not a contract: the exact expression differs across
// driver versions, and ENA builds with XDP multi-buffer support relax the limit
// considerably. It exists to turn "invalid argument" into a number the operator
// can compare against `ip link show`, not to gate the attach — the attach is
// gated by whether the kernel actually accepted it.
func nativeXDPMaxMTU(pageSize int) int {
	return pageSize - frameOverhead - xdpPacketHeadroom - skbSharedInfoAligned
}

// allowGenericXDP reports whether the operator has explicitly accepted the
// generic-mode penalty. Nil-safe, so the caller does not have to pre-check the
// config, and false for a zero-valued config: refusing is the default because a
// generic attach that nobody asked for reads as "XDP is working" while it is
// making the gateway slower than having no XDP at all.
func allowGenericXDP(cfg *gateonv1.EbpfConfig) bool {
	return cfg != nil && cfg.GetAllowGenericXdp()
}

// tcUnsupported lists configured features the TC ingress hook cannot enforce.
//
// The hook decides on the IP header alone: port knocking mutates per-source
// state across packets, JA4/JA3 matching needs the TLS ClientHello, and phantom
// ports and load balancing need XDP_TX/redirect. Falling back from XDP to TC
// therefore silently narrows what is being enforced, and an operator who called
// ShunJA4 would go on believing it was in force. Naming the gap at attach time
// is the difference between a documented trade-off and a hole.
func tcUnsupported(cfg *gateonv1.EbpfConfig) []string {
	if cfg == nil {
		return nil
	}
	var gaps []string
	for _, f := range []struct {
		on   bool
		name string
	}{
		{cfg.GetEnableKnocking(), "enable_knocking"},
		{cfg.GetXdpJa4Blocklist(), "xdp_ja4_blocklist"},
		{cfg.GetAfXdpPhantom(), "af_xdp_phantom"},
		{cfg.GetXdpLoadBalancing(), "xdp_load_balancing"},
	} {
		if f.on {
			gaps = append(gaps, f.name)
		}
	}
	return gaps
}

// nicFacts is what the preflight managed to learn about the target interface.
// Every field is best-effort: a zero value means "could not determine", and the
// diagnosis simply omits the checks that depend on it rather than guessing.
type nicFacts struct {
	Name     string
	Driver   string // sysfs driver name: "ena", "virtio_net", "veth", "" if unknown
	MTU      int
	RXQueues int
	NumCPU   int
	// PageSize is the target host's page size, which sets the native-XDP MTU
	// ceiling. Carried as a field rather than read from os.Getpagesize() inside
	// the checks so the diagnosis is a pure function of its input — the host
	// running the tests is not the host the limit applies to.
	PageSize int
}

// xdpDiagnosis explains why native XDP is unavailable and what to change.
type xdpDiagnosis struct {
	// Summary is one sentence, surfaced through MapStats.LoadError so the
	// dashboard can say why the counters are zero.
	Summary string
	// Remedies are concrete commands, most-likely fix first.
	Remedies []string
}

// mtuBlocker reports whether the interface MTU rules out a native attach.
// Jumbo frames are the single most common cause on EC2, where the VPC default
// is 9001 and the ENA driver rejects anything over roughly a page.
func mtuBlocker(f nicFacts) (cause, remedy string, blocked bool) {
	if f.MTU <= 0 || f.PageSize <= 0 {
		return "", "", false
	}
	limit := nativeXDPMaxMTU(f.PageSize)
	if f.MTU <= limit {
		return "", "", false
	}
	return fmt.Sprintf("MTU %d exceeds the ~%d-byte native-XDP limit for a %d-byte page",
			f.MTU, limit, f.PageSize),
		fmt.Sprintf("sudo ip link set dev %s mtu %d   # costs jumbo-frame throughput inside the VPC",
			f.Name, limit),
		true
}

// queueBlocker reports whether the queue count rules out a native attach. ENA
// needs a dedicated TX queue per RX queue to service XDP_TX/XDP_REDIRECT, so it
// requires combined <= max/2; the driver comes up using every queue it has, so
// the check fails by default on most instance types.
//
// The exact maximum is only readable over ethtool netlink, which would mean an
// ioctl through unsafe or a new dependency for a diagnostic. Instead this infers
// the likely case — queues saturating the CPU count — and hands the operator the
// command that shows the real numbers.
func queueBlocker(f nicFacts) (cause, remedy string, blocked bool) {
	if f.RXQueues <= 0 || f.NumCPU <= 0 || f.RXQueues < f.NumCPU {
		return "", "", false
	}
	return fmt.Sprintf("%d RX queues on %d CPUs, so the driver is likely at its queue maximum "+
			"(native XDP needs combined <= max/2 for the XDP TX rings)", f.RXQueues, f.NumCPU),
		fmt.Sprintf("ethtool -l %s   # then: sudo ethtool -L %s combined %d",
			f.Name, f.Name, f.NumCPU/2),
		true
}

// nativeXDPBlockers collects every preflight reason the native attach could not
// have worked, in the order they are worth trying.
func nativeXDPBlockers(f nicFacts) (causes, remedies []string) {
	for _, check := range []func(nicFacts) (string, string, bool){mtuBlocker, queueBlocker} {
		if cause, remedy, blocked := check(f); blocked {
			causes = append(causes, cause)
			remedies = append(remedies, remedy)
		}
	}
	return causes, remedies
}

// tcRemedy is offered on every failed native attach. The clsact ingress hook
// runs at the same point in the stack as generic XDP but without its two
// per-packet penalties: it has no headroom requirement, so no pskb_expand_head,
// and it does not linearize. On a jumbo-MTU virtual NIC it is strictly the
// better place to drop a packet.
func tcRemedy() string {
	return "or set ebpf.tc_filtering = true to run the same filtering at the clsact ingress " +
		"hook, which has no MTU, headroom or linearization penalty on virtualized NICs"
}

// diagnoseNativeXDP turns a failed native attach into something an operator can
// act on. allowGeneric only changes the wording: the caller decides whether to
// fall back, this explains the situation either way.
func diagnoseNativeXDP(f nicFacts, allowGeneric bool, nativeErr error) xdpDiagnosis {
	causes, remedies := nativeXDPBlockers(f)
	remedies = append(remedies, tcRemedy())

	where := f.Name
	if f.Driver != "" {
		where = fmt.Sprintf("%s (%s)", f.Name, f.Driver)
	}

	why := fmt.Sprintf("driver rejected the native attach: %v", nativeErr)
	if len(causes) > 0 {
		why = joinCauses(causes)
	}

	tail := "refusing generic/SKB mode because it charges every packet the full program cost " +
		"without dropping anything earlier (set ebpf.allow_generic_xdp = true to override)"
	if allowGeneric {
		tail = "falling back to generic/SKB mode because ebpf.allow_generic_xdp is set; " +
			"expect a throughput cost on every packet, not just dropped ones"
	}

	return xdpDiagnosis{
		Summary:  fmt.Sprintf("native XDP unavailable on %s: %s; %s", where, why, tail),
		Remedies: remedies,
	}
}

// joinCauses renders causes as "a; and b" without pulling in strings.Join's
// awkward trailing separator for the single-cause case.
func joinCauses(causes []string) string {
	out := causes[0]
	for _, c := range causes[1:] {
		out += "; and " + c
	}
	return out
}
