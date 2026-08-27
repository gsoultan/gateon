// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package discovery

import (
	"net"
	"strconv"
)

// targetURL builds an http:// URL for a discovered backend.
//
// It exists because every provider built one with fmt.Sprintf("http://%s:%d"),
// which produces an unusable URL for any IPv6 backend: "http://2001:db8::1:80"
// has no valid reading, and url.Parse rejects it. Discovery would hand the load
// balancer a target it could never dial, and the only symptom is a backend that
// silently never receives traffic. net.JoinHostPort brackets the host when it
// needs brackets and leaves a hostname or IPv4 address alone.
//
// A port of zero means "no port", for the A/AAAA fallback where DNS supplies an
// address and nothing else.
func targetURL(host string, port int) string {
	if port <= 0 {
		return "http://" + hostOnly(host)
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// hostOnly brackets a bare IPv6 literal so it can stand in the host position of
// a URL. A hostname or IPv4 address is returned unchanged.
func hostOnly(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// srvWeight converts an SRV record's priority and weight into the single weight
// the load balancer understands.
//
// RFC 2782 is explicit that priority runs the other way from weight: "A client
// MUST attempt to contact the target host with the lowest-numbered priority it
// can reach", while weight is a relative share among hosts of equal priority.
// The previous formula was priority*10 + weight, which is monotonically
// increasing in priority -- so a backup at priority 20 outranked the primary at
// priority 0, and DNS-discovered traffic preferred exactly the hosts the record
// author marked as last resort.
//
// Priority dominates: any host at a lower priority number outranks every host
// at a higher one, whatever their weights. Within one priority, the SRV weight
// orders them. Priorities are clamped rather than wrapped, because a uint16
// priority of 65535 is legal and must not underflow into the top band.
func srvWeight(priority, weight uint16) int32 {
	const (
		// Wider than any legal SRV weight, so a priority step can never be
		// closed by a weight difference.
		band     = 100_000
		maxBands = 16
	)

	p := int32(priority)
	if p >= maxBands {
		p = maxBands - 1
	}
	return (maxBands-p)*band + int32(weight)
}
