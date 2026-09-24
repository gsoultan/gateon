// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"strings"
	"testing"
)

// FuzzHostMatches drives the host comparison that SNI certificate selection
// runs on the raw ServerName of every TLS handshake. On an HTTP/3 entrypoint
// that callback runs on a goroutine crypto/tls starts itself, with no recover,
// so a panic here would take the process down rather than fail one handshake.
func FuzzHostMatches(f *testing.F) {
	for _, s := range [][2]string{
		{"*.example.com", "a.example.com"},
		{"*.example.com", "example.com"},
		{"*.", "x"},
		{"*", ""},
		{"api.example.com.", "API.EXAMPLE.COM:443"},
		{"::1", "[::1]:8080"},
		{"*.example.com", "]:"},
		{"", "anything"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, rh, qh string) {
		got := HostMatches(rh, qh)
		_ = RouteHostIsExact(rh)
		_ = NormalizeHost(qh)
		if rh == "" && !got {
			t.Fatalf("an empty route host must match everything; HostMatches(%q, %q) = false", rh, qh)
		}
		// An exact ASCII route host matches its own spelling in any case. (Some
		// non-ASCII runes upper-case outside their fold orbit, so the property
		// is only claimed for ASCII.)
		if rh != "" && isASCII(rh) && !strings.HasPrefix(rh, "*.") && !strings.ContainsAny(rh, ":[]") && !HostMatches(rh, strings.ToUpper(rh)) {
			t.Fatalf("HostMatches(%q, %q) = false for the same host", rh, strings.ToUpper(rh))
		}
	})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// FuzzRuleIndexing covers the route store's own rule readers, which run on
// every save and at boot for every stored rule.
func FuzzRuleIndexing(f *testing.F) {
	for _, seed := range []string{
		"Host(`api.example.com`) && PathPrefix(`/v1`)",
		"Host(\"a\") && Path(\"/x\")",
		"PathRegex(`^/a`) || Path(`/b`)",
		"Host(`)",
		"PathPrefix(`",
		"Path(",
		"!Host(`x`)",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rule string) {
		host := hostFromRule(rule)
		path, isPrefix, isRegex := rulePathInfo(rule)
		_ = pathFromRule(rule)
		_ = NormalizeHost(host)
		if isPrefix && isRegex && path != "/" {
			t.Fatalf("rulePathInfo(%q) = (%q, prefix, regex): the catch-all must be \"/\"", rule, path)
		}
	})
}
