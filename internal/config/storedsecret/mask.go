// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package storedsecret

import (
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Mask replaces every credential in c with what a caller who may write the
// configuration reads: Sentinel for a stored value, the reference itself for a
// reference, "" for an unset field, and a connection URL with only its
// password replaced. c must be a copy -- the registry hands out its live
// config, and masking that would erase the secrets from the running gateway.
func Mask(c *gateonv1.GlobalConfig) {
	eachSecret(c, func(url bool, p *string) { *p = masked(*p, url) })
}

// Blank empties every credential in c: what a caller who may only read the
// configuration receives. c must be a copy, as for Mask.
func Blank(c *gateonv1.GlobalConfig) {
	eachSecret(c, func(_ bool, p *string) { *p = "" })
}

// Held names every credential field of c that holds Sentinel. No stored
// configuration may: the placeholder is what a client sends to keep a secret,
// and stored as one it would replace the credential with a published string --
// a session key anyone could sign with. The registry refuses such a config
// whichever path it came by.
func Held(c *gateonv1.GlobalConfig) []string {
	var names []string
	for _, f := range fields {
		if p := f.Ptr(c); p != nil && strings.Contains(*p, Sentinel) {
			names = append(names, f.Name)
		}
	}
	for _, l := range lists {
		for i, e := range l.Elements(c) {
			for _, s := range e.Secrets {
				if strings.Contains(*s.Ptr, Sentinel) {
					names = append(names, describe(l, i, e)+"."+s.Name)
				}
			}
		}
	}
	return names
}

// eachSecret calls fn with every credential field of c, the ones in list
// elements included.
func eachSecret(c *gateonv1.GlobalConfig, fn func(url bool, p *string)) {
	if c == nil {
		return
	}
	for _, f := range fields {
		if p := f.Ptr(c); p != nil {
			fn(f.URL, p)
		}
	}
	for _, l := range lists {
		for _, e := range l.Elements(c) {
			for _, s := range e.Secrets {
				fn(false, s.Ptr)
			}
		}
	}
}

func masked(v string, url bool) string {
	switch {
	case v == "" || IsReference(v):
		return v
	case url:
		return maskURL(v)
	default:
		return Sentinel
	}
}

// maskURL hides the credential in a connection URL and leaves the rest
// readable: "postgres://gateon:pw@db/gateon" reads as
// "postgres://gateon:<stored secret>@db/gateon", so the dashboard still shows
// which server and database the gateway uses. A value that cannot be taken
// apart that way and might carry a credential -- a key=value DSN naming a
// password, a user:pass@host form, a password in the query -- is hidden whole.
// A plain SQLite path is not a credential and reads as it is.
func maskURL(v string) string {
	scheme, rest, isURL := strings.Cut(v, "://")
	if !isURL {
		if strings.Contains(v, "@") || mentionsPassword(v) {
			return Sentinel
		}
		return v
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	// An "@" past the authority means a password holding a raw "/", "?" or
	// "#" ended the authority early, and the rest of it is in tail.
	if mentionsPassword(tail) || strings.Contains(tail, "@") {
		return Sentinel
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return v
	}
	user, _, hasPassword := strings.Cut(authority[:at], ":")
	if !hasPassword {
		return v
	}
	return scheme + "://" + user + ":" + Sentinel + authority[at:] + tail
}

func mentionsPassword(s string) bool {
	return strings.Contains(strings.ToLower(s), "password")
}
