// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"strings"
)

// FoldHeaderName returns the variable name a header-folding backend collapses
// name to: the separators '-', '_' and '.' all become '_', and letters are
// upper-cased.
//
// Go canonicalises a header name on '-' alone, so "X-Auth-User", "X_Auth_User"
// and "X.Auth.User" are three distinct header keys to it. PHP/CGI, WSGI and
// nginx with underscores_in_headers on fold all three (and every mixed form)
// to one variable -- HTTP_X_AUTH_USER. A gateway that asserts a trusted
// identity header by its canonical spelling, and strips only that spelling
// from the client, therefore leaves an alias the backend reads instead. That
// is the Traefik ForwardAuth spoof (CVE-2026-88879 dot form, CVE-2026-88011,
// and CVE-2026-39858 for the underscore form) and the Caddy copy_headers
// bypass (CVE-2026-52845).
//
// The fold is the equivalence the backend applies, so comparing folded names
// catches every spelling at once rather than enumerating 3^N separator
// combinations per managed header.
func FoldHeaderName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '-' || c == '.':
			b.WriteByte('_')
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - ('a' - 'A'))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// StripHeaderAliases removes from h every header whose folded form matches the
// folded form of one of the canonical names but is spelled with an underscore
// or a dot -- the alias forms a header-folding backend cannot tell apart from
// the canonical one. The canonical (hyphenated) spelling is never touched:
// callers set it themselves to the value the gateway vouches for.
//
// Only a key that actually contains '_' or '.' can be such an alias, so a
// request of ordinary hyphenated headers -- nearly all of them -- is scanned
// without folding or allocating anything. canonical is a short, mostly static
// list, so the inner comparison runs only for the rare alias key.
func StripHeaderAliases(h http.Header, canonical ...string) {
	if len(h) == 0 || len(canonical) == 0 {
		return
	}
	var toDelete []string
	for key := range h {
		if !strings.ContainsAny(key, "_.") {
			continue
		}
		folded := FoldHeaderName(key)
		for _, c := range canonical {
			if FoldHeaderName(c) == folded {
				toDelete = append(toDelete, key)
				break
			}
		}
	}
	for _, key := range toDelete {
		h.Del(key)
	}
}
