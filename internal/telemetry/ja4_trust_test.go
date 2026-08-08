// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withTrustedPeers swaps the gate's trust predicate for the duration of a test
// and restores it afterwards. See ja4HeaderTrusted for why the seam exists.
func withTrustedPeers(t *testing.T, trusted ...string) {
	t.Helper()
	prev := ja4HeaderTrusted
	ja4HeaderTrusted = func(remoteAddr string) bool {
		for _, ok := range trusted {
			if remoteAddr == ok {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { ja4HeaderTrusted = prev })
}

// TestJA4FromTrustedHeaderIgnoresUntrustedPeer is the regression test for a
// client-supplied fingerprint being taken at face value.
//
// X-JA4-Fingerprint is meant to be written by a TLS terminator in front of the
// gateway, because this process cannot see the handshake it describes. Every
// read site took it straight off the request, so any client could send one. The
// JA4+ value keys reputation, which is what makes that more than cosmetic: a
// caller can rotate the header to drop a bad score, or borrow someone else's to
// spoil theirs.
func TestJA4FromTrustedHeaderIgnoresUntrustedPeer(t *testing.T) {
	const fp = "t13d1516h2_8daaf6152771_b186095e22b6"
	withTrustedPeers(t, "10.0.0.1:4444")

	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"untrusted peer is ignored", "203.0.113.9:4444", ""},
		{"trusted peer is honoured", "10.0.0.1:4444", fp},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-JA4-Fingerprint", fp)
			req.RemoteAddr = tc.remoteAddr

			if got := JA4FromTrustedHeader(req); got != tc.want {
				t.Errorf("JA4FromTrustedHeader() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRealTrustPredicateRejectsUnconfiguredPeer checks the production predicate
// rather than the seam, so the two cannot drift: with no trusted proxies
// configured — the default — nothing may set the header.
func TestRealTrustPredicateRejectsUnconfiguredPeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-JA4-Fingerprint", "spoofed")
	req.RemoteAddr = "203.0.113.9:4444"

	if got := JA4FromTrustedHeader(req); got != "" {
		t.Errorf("unconfigured deployment honoured a client fingerprint: %q", got)
	}
}

// TestGetJA4PlusIgnoresSpoofedHeader checks the gate through the function that
// actually feeds reputation and the challenge pages, not just the helper.
func TestGetJA4PlusIgnoresSpoofedHeader(t *testing.T) {
	const spoof = "SPOOFEDBYCLIENT"
	withTrustedPeers(t, "10.0.0.1:4444")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-JA4-Fingerprint", spoof)
	req.RemoteAddr = "203.0.113.9:4444"

	if got := GetJA4Plus(req); strings.Contains(got, spoof) {
		t.Errorf("spoofed fingerprint reached JA4+: %q", got)
	}

	// The same header from a trusted terminator still gets through, so the gate
	// is not just disabling the feature.
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.Header.Set("X-JA4-Fingerprint", spoof)
	trusted.RemoteAddr = "10.0.0.1:4444"

	if got := GetJA4Plus(trusted); !strings.Contains(got, spoof) {
		t.Errorf("trusted fingerprint did not reach JA4+: %q", got)
	}
}
