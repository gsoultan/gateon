// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func req(method string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	r.Header = http.Header{}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

// referenceHeaderHash is the previous implementation's header component,
// written out longhand: sha256 over the sorted, comma-terminated names of the
// tracked headers, hex-encoded, first 12 characters.
//
// Keeping it here means the precomputed table is checked against the thing it
// replaced rather than against itself.
func referenceHeaderHash(names ...string) string {
	h := sha256.New()
	for _, n := range names {
		_, _ = io.WriteString(h, n)
		_, _ = h.Write([]byte{','})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func TestJA4HMatchesReferenceHeaderHash(t *testing.T) {
	cases := []struct {
		name  string
		hdr   map[string]string
		names []string
	}{
		{name: "neither header", hdr: map[string]string{}},
		{name: "user-agent only", hdr: map[string]string{"User-Agent": "curl/8"}, names: []string{"User-Agent"}},
		{name: "accept-language only", hdr: map[string]string{"Accept-Language": "en"}, names: []string{"Accept-Language"}},
		{
			name:  "both, emitted in sorted order",
			hdr:   map[string]string{"User-Agent": "Mozilla/5.0", "Accept-Language": "en-GB"},
			names: []string{"Accept-Language", "User-Agent"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GenerateJA4H(req(http.MethodGet, tc.hdr))
			want := referenceHeaderHash(tc.names...)
			_, gotHash, ok := strings.Cut(got, "_")
			if !ok {
				t.Fatalf("JA4H %q has no header component", got)
			}
			if gotHash != want {
				t.Errorf("header hash = %q, want %q (the precomputed table has drifted "+
					"from the hash it replaced)", gotHash, want)
			}
		})
	}
}

// The prefix has to keep meaning what it meant: method, version, cookie,
// referer, header count, ALPN.
func TestJA4HPrefixEncoding(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		hdr        map[string]string
		wantPrefix string
	}{
		{name: "GET, no cookie or referer, no tracked headers", method: "GET",
			hdr: map[string]string{}, wantPrefix: "ge11nn0000"},
		{name: "POST with both tracked headers", method: "POST",
			hdr:        map[string]string{"User-Agent": "x", "Accept-Language": "en"},
			wantPrefix: "po11nn0200"},
		{name: "cookie and referer present", method: "GET",
			hdr:        map[string]string{"Cookie": "a=b", "Referer": "http://x/"},
			wantPrefix: "ge11cr0000"},
		{name: "single-letter method is padded", method: "M",
			hdr: map[string]string{}, wantPrefix: "m011nn0000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GenerateJA4H(req(tc.method, tc.hdr))
			if len(got) < 10 || got[:10] != tc.wantPrefix {
				t.Errorf("prefix = %q, want %q (full: %q)", got[:min(10, len(got))], tc.wantPrefix, got)
			}
			if len(got) != 23 {
				t.Errorf("JA4H length = %d, want 23", len(got))
			}
		})
	}
}

// The finding this optimisation surfaced, pinned so nobody has to rediscover it
// from a production incident.
//
// JA4H's header component hashes header *names*. gateon tracks two, so the
// component has four possible values — total, across every client on the
// internet. That is fine for what JA4H is for (grouping traffic by client
// shape) and dangerous for what it is currently used for: pathStatsStore
// mitigates on JA4+ after a single WAF block, so blocking one attacker blocks
// every client sharing their class.
//
// If this test starts failing because the space grew, that is good news and the
// mitigation policy should be revisited in light of it.
func TestJA4HHeaderHashSpace(t *testing.T) {
	seen := make(map[string]struct{})
	for _, hdr := range []map[string]string{
		{},
		{"User-Agent": "a"},
		{"Accept-Language": "b"},
		{"User-Agent": "a", "Accept-Language": "b"},
		// Different values, same names: deliberately collides with the above.
		{"User-Agent": "totally-different", "Accept-Language": "zz-ZZ"},
	} {
		_, h, _ := strings.Cut(GenerateJA4H(req(http.MethodGet, hdr)), "_")
		seen[h] = struct{}{}
	}

	if len(seen) != 4 {
		t.Errorf("header component takes %d distinct values, expected 4; the value "+
			"space changed and the JA4+ mitigation policy assumes this size", len(seen))
	}
}

func BenchmarkGenerateJA4H(b *testing.B) {
	r := req(http.MethodGet, map[string]string{
		"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Accept-Language": "en-GB,en;q=0.9",
		"Accept":          "text/html,application/xhtml+xml",
		"Cookie":          "session=abc",
		"Referer":         "https://example.com/",
	})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = GenerateJA4H(r)
	}
}
