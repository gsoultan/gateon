// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"bytes"
	"net"
)

// peerOutranks decides whether an advertising peer should be master instead of
// this node.
//
// Priority decides it when the two differ. When they are equal the higher
// address wins, which is what VRRP does and, more to the point, is a rule both
// nodes evaluate to opposite answers -- exactly one of them yields.
//
// The equal case used to have no rule at all. A peer at the same priority
// refreshed lastSeen and nothing else, so neither node ever released: both
// waited out three intervals with no master visible, both acquired the VIP, and
// both then sat there receiving each other's adverts and staying master. Two
// nodes holding one address, indefinitely, with nothing logged.
//
// That is not an exotic misconfiguration. Deploying the same config to both
// members of a pair is the obvious thing to do, and priority is exactly the
// field an operator would leave alone.
//
// Addresses are compared as bytes rather than strings: "10.0.0.9" sorts above
// "10.0.0.10" lexically, which would make the winner depend on how the address
// happens to be written.
func peerOutranks(peerPriority, myPriority int32, peerIP, myIP net.IP) bool {
	if peerPriority != myPriority {
		return peerPriority > myPriority
	}

	// Without a usable local address there is no tie-break to apply. Deferring
	// is the safer half: a node that wrongly yields leaves the pair with no
	// master for three intervals, which recovers on its own. A node that wrongly
	// holds gives two masters for one address, which does not.
	if myIP == nil {
		return true
	}
	if peerIP == nil {
		return false
	}
	return bytes.Compare(peerIP.To16(), myIP.To16()) > 0
}

// haInterfaceIP returns the first non-loopback IPv4 address on the named
// interface, which is the identity this node tie-breaks with.
func haInterfaceIP(name string) net.IP {
	if name == "" {
		return nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	return nil
}
