// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package repid

import "testing"

// This package decides what a reputation score is about, and the whole reason it
// exists is that the previous answer — the JA4+ fingerprint alone — named a
// browser build rather than a client, so one attacker could drive a shared score
// to zero and lock out every other user of that browser.
//
// The behavioural half is tested through the middleware that enforces it
// (internal/middleware/reputation_identity_test.go). These cover the identity
// itself: what it separates, what it deliberately does not, and the fast path.

// TestForSeparatesNetworks is the property the fix exists for.
func TestForSeparatesNetworks(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"

	a := For(browser, "203.0.113.10")
	b := For(browser, "198.51.100.20")
	if a == b {
		t.Errorf("two clients on different networks share the identity %q; that is "+
			"the shared-score defect this package exists to remove", a)
	}
}

// TestForKeepsTheClassAsAPrefix pins what makes cross-address correlation still
// possible.
//
// JA4+ is genuinely good at recognising the same client software across
// addresses, and that value is kept: the class is recoverable from the composite,
// so correlation is a query rather than something the identity gives up.
func TestForKeepsTheClassAsAPrefix(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"
	for _, ip := range []string{"203.0.113.10", "198.51.100.20", "2001:db8::1"} {
		if got := ClassOf(For(browser, ip)); got != browser {
			t.Errorf("ClassOf(For(%q, %q)) = %q, want the class back", browser, ip, got)
		}
	}
}

// TestForSharesWithinANetwork records the limit, so nobody reads the fix as more
// than it is.
//
// Scoping is per network, not per person. Two clients behind one NAT still share
// an identity, because from outside the gateway nothing in the request tells them
// apart. Claiming otherwise would repeat the overstatement that made the original
// design look safe.
func TestForSharesWithinANetwork(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"
	if For(browser, "203.0.113.10") != For(browser, "203.0.113.77") {
		t.Error("two clients in one /24 got different identities; scoping is per " +
			"network, and narrowing it further is a deliberate change rather than " +
			"something to discover here")
	}
}

// TestForScopesIPv6ByPrefix covers the v6 half.
func TestForScopesIPv6ByPrefix(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"

	// Same /64.
	if For(browser, "2001:db8:1:2::1") != For(browser, "2001:db8:1:2::99") {
		t.Error("two addresses in one /64 got different identities")
	}
	// Different /64.
	if For(browser, "2001:db8:1:2::1") == For(browser, "2001:db8:1:3::1") {
		t.Error("two different /64s share an identity")
	}
}

// TestForWithoutAFingerprintFallsBackToTheAddress covers the degenerate case.
//
// With no fingerprint the address is the only identity available, and it is
// already as narrow as this function could make it.
func TestForWithoutAFingerprintFallsBackToTheAddress(t *testing.T) {
	if got := For("", "203.0.113.10"); got != "203.0.113.10" {
		t.Errorf(`For("", ip) = %q, want the address`, got)
	}
}

// TestForGivesAnUnparseableAddressItsOwnBucket pins the safe direction.
//
// Falling back to the bare fingerprint would put every client the gateway cannot
// place into the shared class key — reintroducing the exact blast radius this
// package removes, for the requests least able to explain themselves.
func TestForGivesAnUnparseableAddressItsOwnBucket(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"

	unknown := For(browser, "")
	if unknown == browser {
		t.Error("a client with no address got the bare class as its identity, which " +
			"is the shared key the whole package exists to avoid")
	}
	// A value that is not an address at all is kept verbatim rather than
	// collapsed, so malformed values do not all group together.
	if For(browser, "not-an-address") == unknown {
		t.Error("a malformed address was collapsed into the unknown bucket, grouping " +
			"unrelated clients")
	}
}

// TestClassOfHandlesKeysWithNoSeparator covers identities that predate the
// composite or had no fingerprint.
func TestClassOfHandlesKeysWithNoSeparator(t *testing.T) {
	if got := ClassOf("203.0.113.10"); got != "203.0.113.10" {
		t.Errorf("ClassOf on a bare address = %q, want it returned whole", got)
	}
}

// TestIPv4ScopeIsStrict pins the allocation-free fast path.
//
// It exists because the general path parses and formats, and this runs on every
// request through the reputation blocker. Being strict is what lets it skip
// validation: anything not plainly a dotted quad falls through to the parser,
// which is allowed to be slow because it is rare.
func TestIPv4ScopeIsStrict(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want  string
		wantK bool
	}{
		{"203.0.113.10", "203.0.113", true},
		{"1.2.3.4", "1.2.3", true},
		{"255.255.255.255", "255.255.255", true},

		{"2001:db8::1", "", false},    // v6
		{"203.0.113", "", false},      // too few octets
		{"203.0.113.10.5", "", false}, // too many
		{"203.0..10", "", false},      // empty octet
		{"203.0.113.", "", false},     // trailing dot
		{"2030.0.113.10", "", false},  // octet too long
		{"example.com", "", false},    // not an address
		{"", "", false},
	} {
		got, ok := ipv4Scope(tc.in)
		if ok != tc.wantK || got != tc.want {
			t.Errorf("ipv4Scope(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantK)
		}
	}
}

// TestNetworkScopeAgreesWithTheFastPath keeps the two implementations honest.
//
// The fast path exists only as an optimisation of the general one, so any input
// it claims must produce the same scope the parser would.
func TestNetworkScopeAgreesWithTheFastPath(t *testing.T) {
	for _, ip := range []string{
		"203.0.113.10", "1.2.3.4", "10.0.0.1", "255.255.255.255", "0.0.0.0",
	} {
		fast, ok := ipv4Scope(ip)
		if !ok {
			t.Fatalf("the fast path declined %q, which is a plain dotted quad", ip)
		}
		if general := networkScope(ip); general != fast {
			t.Errorf("networkScope(%q) = %q but the fast path gave %q; an "+
				"optimisation that disagrees with what it optimises is a bug",
				ip, general, fast)
		}
	}
}

// TestNetworkScopeHandlesMappedAddresses covers the dual-stack spelling.
func TestNetworkScopeHandlesMappedAddresses(t *testing.T) {
	if got, want := networkScope("::ffff:203.0.113.10"), networkScope("203.0.113.10"); got != want {
		t.Errorf("a v4-mapped address scoped to %q but its v4 form to %q; the same "+
			"host on two listeners must get one identity", got, want)
	}
}

func BenchmarkFor(b *testing.B) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"
	b.ReportAllocs()
	for b.Loop() {
		_ = For(browser, "203.0.113.10")
	}
}
