// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// X-Forwarded-For is a claim, and this is where the gateway decides whether to
// believe it.
//
// The answer feeds more than logging. The client IP drives WAF mitigation,
// IP shunning, geofencing, reputation scoring and rate limiting, so a gateway
// that honours the header from an untrusted peer hands every one of those to
// whoever is sending the request: frame another address, evade a block by
// rotating, or pick a country that is not geofenced. Nothing downstream can
// tell the difference, because by then it is just an IP.
//
// The behaviour is correct today. These tests exist so it stays that way — the
// failure is silent, produces no error, and would look like ordinary traffic
// from whatever address the attacker chose.

const (
	trustedPeer   = "10.0.0.1:5000"
	untrustedPeer = "203.0.113.50:5000"
	spoofed       = "1.2.3.4"
)

func requestFrom(peer string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// The one that matters. An untrusted peer may claim anything; it must be
// ignored in favour of the address the packets actually came from.
func TestForwardedForIsIgnoredFromAnUntrustedPeer(t *testing.T) {
	withTrustedProxies(t, "10.0.0.0/8")

	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", HeaderCloudflareConnectingIP} {
		t.Run(header, func(t *testing.T) {
			got := GetClientIP(requestFrom(untrustedPeer, map[string]string{header: spoofed}), false)
			if got == spoofed {
				t.Errorf("%s from an untrusted peer was believed: client IP = %q.\n"+
					"    Mitigation, geofencing, reputation and rate limiting all key on this "+
					"value, so a client that can choose it can evade or frame with it.", header, got)
			}
			if got != "203.0.113.50" {
				t.Errorf("client IP = %q, want the peer's own address 203.0.113.50", got)
			}
		})
	}
}

// And the other half: a peer that *is* trusted must still be believed, or
// every request behind a legitimate load balancer collapses to the balancer's
// address and per-client defences stop distinguishing anyone.
func TestForwardedForIsHonouredFromATrustedPeer(t *testing.T) {
	withTrustedProxies(t, "10.0.0.0/8")

	got := GetClientIP(requestFrom(trustedPeer, map[string]string{"X-Forwarded-For": spoofed}), false)
	if got != spoofed {
		t.Errorf("client IP = %q, want %q; a trusted proxy's forwarded-for must be "+
			"honoured or every client behind it looks like the proxy", got, spoofed)
	}
}

// Cloudflare's header is only meaningful when Cloudflare is trusted. Honouring
// it otherwise is the same spoof with a different field name.
func TestCloudflareHeaderNeedsCloudflareTrust(t *testing.T) {
	withTrustedProxies(t, "10.0.0.0/8")

	// Trusted peer, but trustCloudflare off: CF-Connecting-IP carries no weight
	// of its own, and X-Forwarded-For is absent, so the peer address stands.
	got := GetClientIP(requestFrom(trustedPeer, map[string]string{HeaderCloudflareConnectingIP: spoofed}), false)
	if got == spoofed {
		t.Errorf("CF-Connecting-IP was honoured with Cloudflare trust disabled: %q", got)
	}
}

// IsTrusted is the decision itself, and it must fail closed on anything it
// cannot parse rather than defaulting to trusted.
func TestIsTrustedFailsClosed(t *testing.T) {
	withTrustedProxies(t, "10.0.0.0/8")

	cases := []struct {
		name string
		addr string
		want bool
	}{
		{name: "inside the trusted range", addr: trustedPeer, want: true},
		{name: "outside it", addr: untrustedPeer, want: false},
		{name: "unparseable", addr: "not-an-address", want: false},
		{name: "empty", addr: "", want: false},
		{name: "hostname rather than IP", addr: "proxy.internal:8080", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTrusted(tc.addr, false); got != tc.want {
				t.Errorf("IsTrusted(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// An empty trusted set must trust nobody. A deployment that forgets to
// configure GATEON_TRUSTED_PROXIES should lose forwarded-for resolution, not
// gain a header anyone can set.
func TestNoTrustedProxiesTrustsNobody(t *testing.T) {
	withTrustedProxies(t)

	got := GetClientIP(requestFrom(trustedPeer, map[string]string{"X-Forwarded-For": spoofed}), false)
	if got == spoofed {
		t.Errorf("forwarded-for was honoured with no trusted proxies configured: %q.\n"+
			"    An unconfigured deployment must fail closed here, not open.", got)
	}
}
