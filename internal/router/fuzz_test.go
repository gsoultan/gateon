// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// FuzzParseRuleAndMatch feeds arbitrary rule text through the parser and the
// matcher. Rules are operator input, but they are parsed lazily on the request
// path and inside the TLS handshake callback, where a panic is either a failed
// request or -- on a QUIC handshake, which crypto/tls runs on a goroutine of
// its own with no recover -- the whole process. The request side is
// attacker-controlled: host, path, method and one header.
func FuzzParseRuleAndMatch(f *testing.F) {
	for _, seed := range []string{
		"Host(`api.example.com`)",
		"Host(\"*.example.com\") && PathPrefix(\"/v1\")",
		"HostRegexp(`^(a|b)\\.example\\.com$`) && Path(`/x`)",
		"PathRegex(`^/api/v[0-9]+/`) && Methods(`GET`, `POST`)",
		"Headers(`X-Env`, `prod`) && Headers(\"X-Tier\", \"gold\")",
		"!Host(`a`) || !!PathPrefix(`/b`) || Methods(\"PUT\")",
		"Methods(`",
		"Headers(`a`,`",
		"Host(``)",
		"!",
		"||",
	} {
		f.Add(seed, "api.example.com:443", "/v1/users", "GET", "X-Env", "prod")
	}
	f.Fuzz(func(t *testing.T, rule, host, path, method, hName, hValue string) {
		m := parseRule(rule)
		_ = m.HasHost()
		_ = m.RequiredHeaders()
		_ = HostFromRule(rule)

		r := &http.Request{
			Method: method,
			Host:   host,
			URL:    &url.URL{Path: path},
			Header: http.Header{},
		}
		r.Header[http.CanonicalHeaderKey(hName)] = []string{hValue}
		_ = m.Match(r)
	})
}

// FuzzNormalizePath checks the properties route selection relies on: the
// result is rooted, carries no "." or ".." segment and no empty segment, and
// normalising it again changes nothing. A path that needs no work must come
// back untouched, since that is the allocation-free fast path.
func FuzzNormalizePath(f *testing.F) {
	for _, seed := range []string{
		"", "/", "//", "/a/b", "/a/../../b", "a/./b/", "/public/../admin",
		"/...", "/a//b//", "/./", "..", "/a/.", "/%2e%2e/x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		out := NormalizePath(p)
		if !needsNormalizing(p) && out != p {
			t.Fatalf("clean path %q was rewritten to %q", p, out)
		}
		if out == "" || out[0] != '/' {
			t.Fatalf("NormalizePath(%q) = %q, not rooted", p, out)
		}
		if strings.Contains(out, "//") {
			t.Fatalf("NormalizePath(%q) = %q, has an empty segment", p, out)
		}
		for _, seg := range strings.Split(out, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("NormalizePath(%q) = %q, still has a %q segment", p, out, seg)
			}
		}
		if again := NormalizePath(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", p, out, again)
		}
	})
}
