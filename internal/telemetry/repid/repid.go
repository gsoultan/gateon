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
// The fix is to make the identity a pair: which software, on which network
// (ADR 0011).
//
// And "which software" is only the part of the fingerprint a client does not
// vary from one request to the next (ADR 0024). The whole JA4+ carried JA4H's
// per-request bits -- the method, whether a Cookie and a Referer were sent --
// so a client the blocker refused became a new, neutral-scored client by
// dropping its Referer: the control was weakest against exactly the client it
// exists to catch. The class a score is kept for is the TLS fingerprint when
// there is one, since the TLS stack fixes it for the connection whatever the
// request says, and otherwise JA4H with those bits taken out (see appendClass).

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
// The composite keeps the fingerprint's class (Class) as its prefix on purpose.
// Cross-address attribution — the genuine strength of JA4+, and the reason it was
// chosen — is still available as a query over keys sharing a prefix. What
// changes is that it is no longer the thing a 403 hangs on.
//
// Every caller hands over the whole fingerprint and this decides which part of
// it counts, so the recording path, every enforcement site and every release
// agree on the class without having to agree on how to cut it.
func For(fingerprint, sourceIP string) string {
	if fingerprint == "" {
		// No fingerprint at all: the address is the only identity available and
		// is already as narrow as this function could make it.
		return sourceIP
	}
	// Built in place and converted once: this runs for the first reputation
	// consumer on every request, and it costs the one allocation the key needs
	// whichever class the fingerprint reduces to.
	var buf [forBufLen]byte
	b := appendClass(buf[:0], fingerprint)
	b = append(b, separator...)
	b = append(b, networkScope(sourceIP)...)
	return string(b)
}

// Class returns the part of a fingerprint a reputation score is kept for: the
// prefix of For's identity, and what ClassOf recovers from one.
//
// An operator's release names the fingerprint a threat recorded, which is the
// whole JA4+; this is how it finds the scores that fingerprint was scored under.
func Class(fingerprint string) string {
	var buf [forBufLen]byte
	return string(appendClass(buf[:0], fingerprint))
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

// Scoped reports whether an identity carries a network scope: whether it is one
// For built from a fingerprint, rather than a bare fingerprint or address.
//
// A fingerprint mitigation keyed on anything else names a client class on
// every network (ADR 0026), so the store refuses to write one and never
// enforces one.
func Scoped(id string) bool {
	return strings.Contains(id, separator)
}

// ScopesOf is the prefix every identity For builds for a class shares: the
// class and the separator. A store finds every network a class is recorded on
// by it, without knowing the networks in advance.
func ScopesOf(class string) string {
	return class + separator
}

// The layout of a JA4H as telemetry.GenerateJA4H writes it, which is what the
// class is cut from: "ge11cr0200_7e33b58890ac" is the method's first two
// letters, the HTTP version, c or n for a Cookie, r or n for a Referer, how many
// of the tracked headers were sent, the ALPN, '_', and a hash of which ones.
// A JA4+ is a JA4, '_', then a JA4H; without TLS the JA4 is empty.
const (
	ja4hLen        = 23 // ten prefix bytes, '_', twelve hash bytes
	ja4hVersionAt  = 2  // two digits
	ja4hCookieAt   = 4  // 'c' or 'n'
	ja4hRefererAt  = 5  // 'r' or 'n'
	ja4hCountAt    = 6  // two digits
	ja4hHashSepAt  = 10 // '_'
	ja4PlusSepChar = '_'

	// volatileMark stands where the class leaves a JA4H field out, so the
	// class keeps JA4H's shape and anyone who can read one can read this.
	volatileMark = '-'

	// forBufLen holds every identity real traffic produces without spilling
	// to the heap: a JA4 is 36 bytes and an IPv6 scope at most 43.
	forBufLen = 96
)

// appendClass appends the part of fingerprint a reputation score is kept for.
//
// With a TLS fingerprint the class is the JA4 alone. The TLS stack writes it
// once per connection from the ClientHello, and nothing a client puts in a
// request can change it; JA4H's half of the JA4+ is exactly the part a request
// can. A stock browser presents one JA4 for every request it makes.
//
// Without one -- plaintext, or TLS terminated in front of the gateway by a
// proxy that does not forward a fingerprint -- the class is JA4H with the bits
// a browser varies from one request to the next marked out: the method (GET for
// a page, POST for its form, OPTIONS for a preflight), and whether a Cookie and
// a Referer were sent (a first visit has no cookie, a typed URL has no referer).
// "ge11cr0200_7e33b58890ac" and "po11nn0200_7e33b58890ac" are one client:
// "_--11--0200_7e33b58890ac". What stays -- the HTTP version, which of
// User-Agent and Accept-Language were sent, and the ALPN -- does not change
// between one browser's requests, and still tells a browser from curl.
//
// Anything that is not a JA4+ or a JA4H is its own class, whole, as before.
func appendClass(dst []byte, fingerprint string) []byte {
	ja4, ja4h, ok := splitJA4Plus(fingerprint)
	switch {
	case !ok:
		return append(dst, fingerprint...)
	case ja4 != "":
		return append(dst, ja4...)
	default:
		dst = append(dst, ja4PlusSepChar)
		start := len(dst)
		dst = append(dst, ja4h...)
		dst[start], dst[start+1] = volatileMark, volatileMark
		dst[start+ja4hCookieAt], dst[start+ja4hRefererAt] = volatileMark, volatileMark
		return dst
	}
}

// splitJA4Plus splits a JA4+ into its JA4 and JA4H, reporting false for
// anything that does not end in a JA4H. A bare JA4H is accepted too, with an
// empty JA4, so that a key built from the HTTP half alone lands on the same
// class as the JA4+ it came from.
func splitJA4Plus(fp string) (ja4, ja4h string, ok bool) {
	n := len(fp)
	if n < ja4hLen || !isJA4H(fp[n-ja4hLen:]) {
		return "", "", false
	}
	ja4h = fp[n-ja4hLen:]
	switch {
	case n == ja4hLen:
		return "", ja4h, true
	case fp[n-ja4hLen-1] != ja4PlusSepChar:
		return "", "", false
	default:
		return fp[:n-ja4hLen-1], ja4h, true
	}
}

// isJA4H reports whether s has the fixed parts of GenerateJA4H's layout. The
// method and ALPN bytes are whatever the request carried, so they are not
// checked; the cookie and referer flags are. A referer flag is never a hex
// digit, so the tail of a JA4 -- hex hashes either side of a '_' -- never passes
// for a JA4H even where its digits happen to line up.
func isJA4H(s string) bool {
	if len(s) != ja4hLen || s[ja4hHashSepAt] != ja4PlusSepChar {
		return false
	}
	if !isDigit(s[ja4hVersionAt]) || !isDigit(s[ja4hVersionAt+1]) ||
		!isDigit(s[ja4hCountAt]) || !isDigit(s[ja4hCountAt+1]) {
		return false
	}
	if c, r := s[ja4hCookieAt], s[ja4hRefererAt]; (c != 'c' && c != 'n') || (r != 'r' && r != 'n') {
		return false
	}
	for i := ja4hHashSepAt + 1; i < ja4hLen; i++ {
		if !isDigit(s[i]) && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

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

	if addr.Is4In6() {
		// A v4-mapped address is the same host as its v4 form, and a client on a
		// dual-stack listener can present either spelling. Unmap and take the fast
		// path so both produce the *same* scope string: the fast path returns a
		// substring ("203.0.113") while the general path formats a prefix
		// ("203.0.113.0/24"), so without this the two spellings of one host became
		// two identities and a score never accumulated across them.
		addr = addr.Unmap()
		if scope, ok := ipv4Scope(addr.String()); ok {
			return scope
		}
	}

	bits := ipv4ScopeBits
	if addr.Is6() {
		bits = ipv6ScopeBits
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
