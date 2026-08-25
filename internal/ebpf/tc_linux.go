// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tcFilterName identifies our filter in `tc filter show dev <iface> ingress`,
// so an operator can see who owns it without guessing.
const tcFilterName = "gateon_ingress"

// tcFilterPriority is the filter's position in the ingress chain. 1 puts us
// ahead of anything a CNI or tc script installs at the default priority, which
// is what we want: a shunned source should not reach another program's logic.
const tcFilterPriority = 1

// attachTC attaches the ingress program at the clsact hook, preferring TCX.
//
// This is the right hook for a virtualized NIC. It runs at the same point as
// generic XDP — after the skb exists — but without generic XDP's two penalties:
// no 256-byte headroom requirement, so no pskb_expand_head(), and no
// skb_linearize(). It also has no MTU ceiling, so it works on a default EC2
// instance at MTU 9001 where native XDP cannot attach at all.
//
// TCX (kernel >= 6.6) is tried first because the kernel owns the lifecycle: the
// program detaches when the link closes, with no qdisc left behind. Older
// kernels — including the 6.1 line that Amazon Linux 2023 ships — need the
// clsact qdisc and a bpf filter managed by hand.
func attachTC(prog *ebpf.Program, iface *net.Interface) (io.Closer, string, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err == nil {
		return l, attachModeTCX, nil
	}

	tcxErr := err
	logger.L.LogInfo("TCX unavailable (needs kernel 6.6+); using the clsact qdisc instead",
		"interface", iface.Name, "error", tcxErr)

	closer, err := attachClsact(prog, iface)
	if err != nil {
		return nil, "", fmt.Errorf("tcx attach failed (%w); clsact attach failed: %w", tcxErr, err)
	}
	return closer, attachModeClsact, nil
}

// clsactAttachment records what has to be undone at teardown. The qdisc is only
// removed if we created it: deleting a clsact qdisc takes every filter on it
// with it, including egress filters belonging to a CNI or another agent, so
// tearing down one we merely borrowed would be someone else's outage.
type clsactAttachment struct {
	filter    netlink.Filter
	qdisc     netlink.Qdisc // nil when the qdisc pre-existed
	ifaceName string
}

func (a *clsactAttachment) Close() error {
	var errs []error
	if err := netlink.FilterDel(a.filter); err != nil {
		errs = append(errs, fmt.Errorf("delete tc filter on %s: %w", a.ifaceName, err))
	}
	if a.qdisc != nil {
		if err := netlink.QdiscDel(a.qdisc); err != nil {
			errs = append(errs, fmt.Errorf("delete clsact qdisc on %s: %w", a.ifaceName, err))
		}
	}
	return errors.Join(errs...)
}

// ensureClsact returns the clsact qdisc for the interface, creating it if
// absent. The second result is non-nil only when we created it, which is what
// decides whether teardown may remove it.
func ensureClsact(nl netlink.Link, ifaceName string) (owned netlink.Qdisc, err error) {
	existing, err := netlink.QdiscList(nl)
	if err != nil {
		return nil, fmt.Errorf("list qdiscs on %s: %w", ifaceName, err)
	}
	for _, q := range existing {
		if q.Type() == "clsact" {
			return nil, nil
		}
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: nl.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("add clsact qdisc to %s: %w", ifaceName, err)
	}
	return qdisc, nil
}

// attachClsact installs the program as a direct-action bpf filter on the
// interface's clsact ingress hook.
func attachClsact(prog *ebpf.Program, iface *net.Interface) (io.Closer, error) {
	nl, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, fmt.Errorf("resolve link %s: %w", iface.Name, err)
	}

	owned, err := ensureClsact(nl, iface.Name)
	if err != nil {
		return nil, err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			// Host byte order; the netlink layer swaps it on the wire.
			Protocol: unix.ETH_P_ALL,
			Priority: tcFilterPriority,
		},
		Fd:   prog.FD(),
		Name: tcFilterName,
		// Direct action: the program's TC_ACT_* return value is the verdict,
		// with no separate tc action object to install and account for.
		DirectAction: true,
	}

	// Replace rather than add so a filter left behind by an unclean shutdown
	// does not permanently block reattachment.
	if err := netlink.FilterReplace(filter); err != nil {
		if owned != nil {
			_ = netlink.QdiscDel(owned)
		}
		return nil, fmt.Errorf("install tc filter on %s: %w", iface.Name, err)
	}

	return &clsactAttachment{filter: filter, qdisc: owned, ifaceName: iface.Name}, nil
}
