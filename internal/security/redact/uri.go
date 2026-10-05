// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redact

import (
	"net/url"
	"strings"
)

// URI returns uri with the value of every credential-carrying query parameter
// replaced by Mask. Parameter names, their order, the path and every other
// value are kept byte for byte, so "?api_key=s3cr3t&page=2" becomes
// "?api_key=[REDACTED]&page=2": a trace still says which parameters the client
// sent and what the harmless ones said.
//
// A parameter carries a credential when its name says so (IsCredentialParam,
// after percent-decoding the name, because the server decodes it) or its value
// has the shape of one whatever it is called (IsCredentialValue). Both '&' and
// ';' separate parameters, since some backends split on either.
//
// It works on anything with a query string -- a request target, the
// host-prefixed form a trace stores, an absolute Referer or Location -- and
// returns uri itself, with no allocation, when there is nothing to hide.
func URI(uri string) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return uri
	}
	var spans []span
	for i := q + 1; i < len(uri); {
		name, value, at, next := nextParam(uri, i)
		if value != "" && (IsCredentialParam(paramName(name)) || IsCredentialValue(value)) {
			spans = append(spans, span{start: at, end: at + len(value), repl: Mask})
		}
		i = next
	}
	return apply(uri, spans)
}

// nextParam reads the parameter that starts at i in s: its name, its value
// (empty when it has none), the offset of the value in s, and where the next
// parameter starts.
func nextParam(s string, i int) (name, value string, at, next int) {
	end := i
	for end < len(s) && s[end] != '&' && s[end] != ';' {
		end++
	}
	seg := s[i:end]
	eq := strings.IndexByte(seg, '=')
	if eq < 0 {
		return seg, "", end, end + 1
	}
	return seg[:eq], seg[eq+1:], i + eq + 1, end + 1
}

// paramName is a parameter name as the server will read it. "api%5Fkey" is
// api_key to every framework that decodes its query, so it is matched as one.
func paramName(name string) string {
	if strings.ContainsAny(name, "%+") {
		if d, err := url.QueryUnescape(name); err == nil {
			return d
		}
	}
	return name
}

// tokenPrefixes are the starts of values that are credentials whatever the
// parameter carrying them is called: the gateway's own API tokens (ADR 0050),
// PASETO tokens (the gateway's sessions among them, ADR 0041), and an
// Authorization value percent- or form-encoded into a parameter.
var tokenPrefixes = []string{
	"gateon_tok_",
	"v1.local.", "v1.public.", "v2.local.", "v2.public.",
	"v3.local.", "v3.public.", "v4.local.", "v4.public.",
	"bearer%20", "bearer+", "basic%20", "basic+",
}

// IsCredentialValue reports whether a value has the shape of a credential: one
// of tokenPrefixes, or a JSON Web Token (a base64url header that starts
// `{"` and at least two dots).
func IsCredentialValue(v string) bool {
	for _, p := range tokenPrefixes {
		if len(v) > len(p) && strings.EqualFold(v[:len(p)], p) {
			return true
		}
	}
	return strings.HasPrefix(v, "eyJ") && strings.Count(v, ".") >= 2
}
