// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package repid

import (
	"strings"
	"testing"
)

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

// Fingerprints as the gateway composes them: a JA4, '_', then a JA4H -- with
// the JA4 empty for a plaintext client.
const (
	tlsJA4       = "t13d1516h2_8daaf6152771_b0da82dd1658"
	otherTLSJA4  = "t13d1715h2_5b57614c22b0_3d5424432f57"
	browserJA4H  = "ge11cr0200_7e33b58890ac" // GET, HTTP/1.1, cookie, referer, UA + Accept-Language
	curlJA4H     = "ge11nn0100_c1e8ae8b2d9b" // GET, HTTP/1.1, no cookie, no referer, UA only
	plaintextKey = "_--11--0200_7e33b58890ac"
)

// TestClassIgnoresWhatABrowserVariesPerRequest is the property ADR 0024 adds:
// the bits of JA4H a browser changes from one request to the next -- the
// method, and whether a Cookie and a Referer were sent -- are not part of the
// identity, so changing them does not make a refused client someone new.
func TestClassIgnoresWhatABrowserVariesPerRequest(t *testing.T) {
	variants := []string{
		"ge11cr0200_7e33b58890ac", // the page
		"ge11nr0200_7e33b58890ac", // first visit: no cookie yet
		"ge11cn0200_7e33b58890ac", // typed URL: no referer
		"po11cr0200_7e33b58890ac", // the page's form
		"op11nn0200_7e33b58890ac", // a preflight
		"he11nn0200_7e33b58890ac", // HEAD
	}
	for _, ja4 := range []string{"", tlsJA4} {
		want := For(ja4+"_"+variants[0], "203.0.113.10")
		for _, v := range variants[1:] {
			if got := For(ja4+"_"+v, "203.0.113.10"); got != want {
				t.Errorf("JA4 %q: JA4H %s gives identity %q, %s gives %q: a per-request bit "+
					"made the same client someone new", ja4, variants[0], want, v, got)
			}
		}
	}
}

// TestClassIsTheJA4WhenThereIsOne: the TLS stack fixes the JA4 for the
// connection, so with one the whole of JA4H -- including which headers were
// sent -- stays out of the class.
func TestClassIsTheJA4WhenThereIsOne(t *testing.T) {
	if got, want := For(tlsJA4+"_"+browserJA4H, "203.0.113.10"), tlsJA4+"|203.0.113"; got != want {
		t.Errorf("For(JA4+) = %q, want %q", got, want)
	}
	if For(tlsJA4+"_"+browserJA4H, "203.0.113.10") != For(tlsJA4+"_"+curlJA4H, "203.0.113.10") {
		t.Error("a TLS client changed its identity by changing which headers it sent")
	}
	if For(tlsJA4+"_"+browserJA4H, "203.0.113.10") == For(otherTLSJA4+"_"+browserJA4H, "203.0.113.10") {
		t.Error("two different TLS stacks on one network share an identity: the class no longer " +
			"separates client software, and one client's score refuses the whole network")
	}
}

// TestClassKeepsWhatABrowserDoesNotVary pins the other side for a plaintext
// client: the HTTP version and which of User-Agent and Accept-Language were sent
// stay in the class. They do not change between one browser's requests, and
// they are what still tells a browser from curl on the same network.
func TestClassKeepsWhatABrowserDoesNotVary(t *testing.T) {
	if got := For("_"+browserJA4H, "203.0.113.10"); got != plaintextKey+"|203.0.113" {
		t.Errorf("For(plaintext JA4+) = %q, want %q", got, plaintextKey+"|203.0.113")
	}
	for _, other := range []string{
		"_" + curlJA4H,             // not a browser
		"_ge20cr0200_7e33b58890ac", // HTTP/2
		"_ge11cr0100_2f3d1f8b0a10", // one tracked header fewer
		"_ge11cr02h2_7e33b58890ac", // TLS without a JA4: its ALPN
	} {
		if For(other, "203.0.113.10") == For("_"+browserJA4H, "203.0.113.10") {
			t.Errorf("%q and %q share an identity; the class dropped a bit that separates clients",
				other, "_"+browserJA4H)
		}
	}
	// One tracked header each, so the same count: only the hash of which one
	// was sent tells a client that sends User-Agent from one that sends
	// Accept-Language.
	if For("_ge11nn0100_c1e8ae8b2d9b", "203.0.113.10") == For("_ge11nn0100_5f2b8c1a9e30", "203.0.113.10") {
		t.Error("two plaintext clients sending different headers share an identity: the class dropped the header hash")
	}
}

// TestABareJA4HHasItsJA4PlusClass: a key built from the HTTP half alone -- the
// rate limiter's "ja4h" strategy -- lands on the class of the plaintext JA4+ it
// came from, and so gets the same immunity to per-request bits.
func TestABareJA4HHasItsJA4PlusClass(t *testing.T) {
	if Class(browserJA4H) != Class("_"+browserJA4H) {
		t.Errorf("Class(%q) = %q but Class(%q) = %q", browserJA4H, Class(browserJA4H),
			"_"+browserJA4H, Class("_"+browserJA4H))
	}
	if Class("po11nn0200_7e33b58890ac") != Class(browserJA4H) {
		t.Error("a bare JA4H kept its per-request bits")
	}
}

// TestClassLeavesOtherFingerprintsWhole: anything that is not a JA4+ or a JA4H
// is its own class, whole, as before -- including a JA4 on its own, whose hex
// hash must never be mistaken for a JA4H.
func TestClassLeavesOtherFingerprintsWhole(t *testing.T) {
	for _, fp := range []string{
		tlsJA4,
		"ja4-shared-browser-A",
		tlsJA4 + "_scoped",
		"t13d1516h2_release_by_address_a1_b2",
		"ge11xr0200_7e33b58890ac", // not a cookie flag
		"ge11cx0200_7e33b58890ac", // not a referer flag
		"ge11cr0200_7e33b58890aZ", // not hex
		"geAAcr0200_7e33b58890ac", // not a version
		"x" + browserJA4H,         // no separator before the JA4H
		lookalikeJA4,
	} {
		if got := Class(fp); got != fp {
			t.Errorf("Class(%q) = %q, want it whole", fp, got)
		}
	}
	// Its last 23 bytes put digits, a 'c' and the '_' exactly where a JA4H has
	// them; only the referer flag, which is never a hex digit, rules the tail out.
	if tail := lookalikeJA4[len(lookalikeJA4)-ja4hLen:]; isJA4H(tail) {
		t.Errorf("the tail of the JA4 %q, %q, passed for a JA4H", lookalikeJA4, tail)
	}
}

// lookalikeJA4 is a JA4 whose hashes happen to line up with a JA4H's layout.
const lookalikeJA4 = "t13d1516h2_000012c53400_b0da82dd1658"

// TestClassOfRecoversTheClass keeps For and ClassOf consistent with Class, which
// is how an operator's release finds a fingerprint's scores.
func TestClassOfRecoversTheClass(t *testing.T) {
	for _, fp := range []string{tlsJA4 + "_" + browserJA4H, "_" + browserJA4H, browserJA4H, "ja4-other"} {
		for _, ip := range []string{"203.0.113.10", "2001:db8::1", ""} {
			if got, want := ClassOf(For(fp, ip)), Class(fp); got != want {
				t.Errorf("ClassOf(For(%q, %q)) = %q, want Class = %q", fp, ip, got, want)
			}
		}
	}
}

func BenchmarkFor(b *testing.B) {
	for _, tc := range []struct{ name, fp, ip string }{
		{"ja4", tlsJA4, "203.0.113.10"},
		{"tls-ja4plus", tlsJA4 + "_" + browserJA4H, "203.0.113.10"},
		{"plaintext-ja4plus", "_" + browserJA4H, "203.0.113.10"},
		{"tls-ja4plus-ipv6", tlsJA4 + "_" + browserJA4H, "2001:db8:1:2::10"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = For(tc.fp, tc.ip)
			}
		})
	}
}

// TestScopedTellsANetworkScopedIdentityFromABareOne pins the check a fingerprint
// block's store makes before it writes or enforces a key (ADR 0026). A bare
// fingerprint names a browser build on every network, which is the block this
// package exists to stop; an address alone is not a fingerprint block at all.
func TestScopedTellsANetworkScopedIdentityFromABareOne(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"
	for _, ip := range []string{"203.0.113.10", "2001:db8::1", ""} {
		if id := For(browser, ip); !Scoped(id) {
			t.Errorf("For(browser, %q) = %q reads as unscoped; the store would refuse "+
				"the block it was asked to keep", ip, id)
		}
	}
	for _, bare := range []string{browser, Class(browser), For("", "203.0.113.10"), "2001:db8::1", ""} {
		if Scoped(bare) {
			t.Errorf("Scoped(%q) = true; a key without a network would be enforced on "+
				"every network", bare)
		}
	}
}

// TestScopesOfFindsEveryNetworkOfAClassAndNoOtherClass pins how a release by
// fingerprint finds every network the build is blocked on: by the prefix
// ScopesOf gives. The separator is part of that prefix because one class's text
// can begin another's; matched on the class alone, releasing one build would
// lift the other's blocks too.
func TestScopesOfFindsEveryNetworkOfAClassAndNoOtherClass(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658"
	prefix := ScopesOf(Class(browser))
	for _, ip := range []string{"203.0.113.10", "198.51.100.20", "2001:db8::1"} {
		if id := For(browser, ip); !strings.HasPrefix(id, prefix) {
			t.Errorf("For(browser, %q) = %q does not start with %q; a release by "+
				"fingerprint would miss this network", ip, id, prefix)
		}
	}

	const longer = browser + "ab"
	if c := Class(longer); c == Class(browser) || !strings.HasPrefix(c, Class(browser)) {
		t.Fatalf("precondition: Class(%q) = %q should extend Class(browser) = %q",
			longer, c, Class(browser))
	}
	if id := For(longer, "203.0.113.10"); strings.HasPrefix(id, prefix) {
		t.Errorf("For(%q, ...) = %q starts with %q; releasing one build would lift "+
			"another's blocks", longer, id, prefix)
	}
}
