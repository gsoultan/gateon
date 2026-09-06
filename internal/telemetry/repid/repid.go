// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package repid

import (
	"net/netip"
	"strings"
)

// This package decides what a reputation score is *about*.
//
// It used to be the JA4+ fingerprint alone, and that was wrong in a way no test
// could see, because JA4+ does not identify a client. GenerateJA4H is built from
// the HTTP method, protocol version, whether a cookie is present, whether a
// referer is present, the header count, the header-name mask and
// Accept-Language. JA4 is the TLS stack and its version. Neither reads an
// address, a connection or a credential, so both are properties of the
// *software* making the request.
//
// Two different people running the same Chrome build in the same language, both
// carrying a cookie, therefore produce the same JA4+ — and the reputation
// blocker, which is attached to every route unconditionally (router.go), refuses
// with 403 below a score of 2.0. One attacker on an unmodified browser could
// drive that shared score to zero and take every other user of that browser
// down with them, everywhere. The attacker's advantage was looking *ordinary*.
//
// The fix is to make the identity a pair: which software, on which network.

const (
	// separator joins the fingerprint to the network scope. It is a byte
	// that appears in neither half — JA4+ is hex, dots and underscores, and a
	// network prefix is dotted quad or hex — so the composite can be split back
	// apart to recover the class for cross-network correlation.
	separator = "|"

	// scopeUnknown is the network scope for a client whose address could not
	// be parsed. It is a distinct bucket rather than a fallback to the bare
	// fingerprint: falling back would put every unparseable client into the
	// shared class key and reintroduce exactly the blast radius this exists to
	// remove, for the requests least able to explain themselves.
	scopeUnknown = "?"

	// ipv4ScopeBits and ipv6ScopeBits set how wide a "network" is.
	//
	// /24 and /64 are the smallest units an operator is normally delegated, so
	// they are the narrowest scope that still survives a client legitimately
	// changing address — a phone moving between cells, a DHCP lease renewing.
	// Narrower and a NAT pool would fragment into scores that never accumulate;
	// wider and one abusive customer of a large hosting provider would start
	// taking their neighbours down again.
	ipv4ScopeBits = 24
	ipv6ScopeBits = 64
)

// For returns the identity a reputation score is recorded under and
// enforced against.
//
// Both sides must agree or the control silently stops working: score under one
// key and read another and every lookup returns the neutral 100, which reads as
// "this client is fine" rather than as "nobody is checking". That is why this is
// one function called from both the threat-recording path and every enforcement
// site rather than a convention.
//
// The composite keeps the fingerprint as its prefix on purpose. Cross-address
// attribution — the genuine strength of JA4+, and the reason it was chosen — is
// still available as a query over keys sharing a prefix. What changes is that it
// is no longer the thing a 403 hangs on.
func For(fingerprint, sourceIP string) string {
	if fingerprint == "" {
		// No fingerprint at all: the address is the only identity available and
		// is already as narrow as this function could make it.
		return sourceIP
	}
	return fingerprint + separator + networkScope(sourceIP)
}

// ClassOf returns the fingerprint half of a composite identity.
//
// This is how a dashboard or a correlation pass gets back to "every client
// running this browser", which is what JA4+ is genuinely good at. A key with no
// separator predates the composite or had no fingerprint, and is returned whole.
func ClassOf(repID string) string {
	if i := strings.LastIndex(repID, separator); i >= 0 {
		return repID[:i]
	}
	return repID
}

// networkScope reduces an address to the network it belongs to.
//
// Returning the prefix as a string rather than a netip.Prefix keeps the result
// usable as a map key with no further formatting, and this runs on the request
// path where the reputation blocker reads it.
func networkScope(ip string) string {
	if ip == "" {
		return scopeUnknown
	}

	// IPv4 fast path. The /24 is exactly the text before the third dot, so it is
	// a substring — no parse, no format, no allocation. This matters because the
	// reputation blocker carrying this call is on every route's chain, so the
	// general path's ParseAddr + Prefix + String would be paid by every proxied
	// request on the gateway whether or not it has ever seen an attack.
	if scope, ok := ipv4Scope(ip); ok {
		return scope
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// A value that is not an address at all. Keep it verbatim rather than
		// collapsing to the unknown bucket: it still separates this client from
		// others, and discarding it would group every malformed value together.
		return ip
	}

	bits := ipv4ScopeBits
	if addr.Is6() && !addr.Is4In6() {
		bits = ipv6ScopeBits
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ip
	}
	return prefix.String()
}

// ipv4Scope returns the /24 of a dotted-quad address as a substring of the
// input, reporting false for anything that is not plainly IPv4.
//
// Deliberately strict: three dots, digits everywhere else, at least one digit
// per octet. Anything else — an IPv6 address, a hostname, a malformed value —
// falls through to the general path, which parses properly and is allowed to be
// slow because it is rare. Being strict here is what lets the fast path skip
// validation entirely rather than half-validating and hoping.
func ipv4Scope(ip string) (string, bool) {
	dots, thirdDot, digits := 0, -1, 0
	for i := 0; i < len(ip); i++ {
		switch c := ip[i]; {
		case c == '.':
			if digits == 0 {
				return "", false // empty octet
			}
			digits = 0
			dots++
			if dots == 3 {
				thirdDot = i
			}
		case c >= '0' && c <= '9':
			digits++
			if digits > 3 {
				return "", false
			}
		default:
			return "", false // ':' for IPv6, or anything not an address
		}
	}
	if dots != 3 || digits == 0 || thirdDot < 0 {
		return "", false
	}
	return ip[:thirdDot], true
}
