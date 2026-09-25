// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

// hash12 is JA4's truncated hash of an already-formatted list.
func hash12(list string) string {
	sum := sha256.Sum256([]byte(list))
	return hex.EncodeToString(sum[:])[:12]
}

// chromeHello is the ClientHello the JA4 specification works through
// (FoxIO-LLC/ja4, technical_details/JA4.md), with the GREASE values a Chrome
// client adds: one in the cipher list, two among the extensions and one in
// supported_versions. Chrome picks them at random for every connection.
func chromeHello(grease uint16) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName: "example.com",
		CipherSuites: []uint16{
			grease, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			grease, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
			0x4469, grease ^ 0x1010,
		},
		SignatureSchemes: []tls.SignatureScheme{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		},
		SupportedVersions: []uint16{grease, tls.VersionTLS13, tls.VersionTLS12},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
}

// TestJA4MatchesTheSpecification: the fingerprint is only worth having if it is
// the one everyone else computes -- threat feeds, other gateways, the spec's
// own worked example. Gateon's differed in six ways: GREASE values were
// hashed in, the version came from the first supported_versions entry (GREASE,
// for Chrome, so "00"), SNI and ALPN were not left out of the extension hash,
// the signature algorithms were missing from it, values were hashed without
// zero padding, and an ALPN-count field no JA4 has sat in the middle.
func TestJA4MatchesTheSpecification(t *testing.T) {
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got := CalcFingerprints(chromeHello(0x0a0a)).JA4; got != want {
		t.Fatalf("JA4 of the specification's example = %q, want %q", got, want)
	}
}

// TestJA4IsStableAcrossGREASE: a client's fingerprint must not change between
// its connections. With GREASE hashed in, Chrome's did on nearly every one, so
// reputation, rate limits and blocks keyed on it never saw the same client
// twice.
func TestJA4IsStableAcrossGREASE(t *testing.T) {
	first := CalcFingerprints(chromeHello(0x0a0a)).JA4
	for _, g := range []uint16{0x1a1a, 0x5a5a, 0xdada, 0xfafa} {
		if got := CalcFingerprints(chromeHello(g)).JA4; got != first {
			t.Errorf("GREASE %#04x gave %q, GREASE 0x0a0a gave %q", g, got, first)
		}
	}
	// RFC 8701 reserves GREASE in signature_algorithms too.
	hello := chromeHello(0x3a3a)
	hello.SignatureSchemes = append([]tls.SignatureScheme{0x3a3a}, hello.SignatureSchemes...)
	if got := CalcFingerprints(hello).JA4; got != first {
		t.Errorf("a GREASE signature algorithm gave %q, want %q", got, first)
	}
}

// TestJA4EdgeCases pins the specification's rules for what a hello leaves out.
func TestJA4EdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hello *tls.ClientHelloInfo
		want  string
	}{
		{
			// No SNI extension is "i"; no ALPN is "00"; with no signature
			// algorithms the extension list is hashed without the trailing "_".
			name: "no SNI, ALPN or signature algorithms",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      []uint16{0xc02f, 0x1301},
				Extensions:        []uint16{0x000a, 0x002b},
				SupportedVersions: []uint16{tls.VersionTLS13},
			},
			want: "t13i020200_" + hash12("1301,c02f") + "_" + hash12("000a,002b"),
		},
		{
			// Nothing to hash is twelve zeros, not the hash of "".
			name: "no ciphers or extensions",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS12},
			},
			want: "t12i000000_000000000000_000000000000",
		},
		{
			// The highest version, not the first listed.
			name: "versions listed lowest first",
			hello: &tls.ClientHelloInfo{
				CipherSuites:      []uint16{0x1301},
				Extensions:        []uint16{0x002b},
				SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
			},
			want: "t13i010100_" + hash12("1301") + "_" + hash12("002b"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CalcFingerprints(tc.hello).JA4; got != tc.want {
				t.Errorf("JA4 = %q, want %q", got, tc.want)
			}
		})
	}
}
