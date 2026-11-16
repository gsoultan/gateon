// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"os"
	"strings"
	"sync"
)

// EnvForwardInternalHeaders names the framework-internal headers an operator
// lets clients send through, comma-separated, for a backend that depends on
// one of them (an API whose clients tunnel DELETE through POST with
// X-HTTP-Method-Override, say). Empty, the default on every tier, forwards
// none. A name that is not in InternalHeaders is ignored.
const EnvForwardInternalHeaders = "GATEON_FORWARD_INTERNAL_HEADERS"

// InternalHeaders are request headers that mean something only between a
// framework and the infrastructure in front of it. A client has no business
// sending one, and a backend that believes one from a client is bypassed:
//
//   - X-Middleware-Subrequest marks a request Next.js issued to itself, so
//     its middleware is skipped; sent by a client it skips the authorization
//     that middleware performs (CVE-2025-29927, CVSS 9.1).
//   - X-Original-Url, X-Rewrite-Url, X-Original-Uri and X-Override-Url tell
//     Symfony, Laravel, IIS URL Rewrite and nginx auth_request backends which
//     path to serve. The gateway routes, filters and authenticates on the
//     path in the request line; the backend then serves the one in the
//     header, so "/public" at the gateway is "/admin" at the origin.
//   - X-Http-Method-Override, X-Http-Method and X-Method-Override make a
//     POST a DELETE the same way: every method the gateway matched on,
//     limited or allowed is not the method the backend runs.
//
// It is the same defect as the header-alias spoof FoldHeaderName describes --
// the edge and the origin disagreeing about what a request says -- one header
// family over. The gateway is the infrastructure in front of the framework, so
// the names are its to assert or to withhold.
//
// Canonical MIME spelling, which is what an http.Header is keyed by.
var InternalHeaders = [...]string{
	"X-Middleware-Subrequest",
	"X-Original-Url",
	"X-Rewrite-Url",
	"X-Original-Uri",
	"X-Override-Url",
	"X-Http-Method-Override",
	"X-Http-Method",
	"X-Method-Override",
}

// minInternalHeaderLen is len("X-Http-Method"), the shortest entry. An alias
// has the same length as the name it folds to.
const minInternalHeaderLen = 13

// internalHeaderIndex returns the position of key in InternalHeaders, or -1.
// key is a canonical header key. A switch and not a map: the entrypoint runs
// this for every header of every request, and the compiler turns the switch
// into a length check and at most one comparison.
func internalHeaderIndex(key string) int {
	switch key {
	case "X-Middleware-Subrequest":
		return 0
	case "X-Original-Url":
		return 1
	case "X-Rewrite-Url":
		return 2
	case "X-Original-Uri":
		return 3
	case "X-Override-Url":
		return 4
	case "X-Http-Method-Override":
		return 5
	case "X-Http-Method":
		return 6
	case "X-Method-Override":
		return 7
	}
	return -1
}

// forwardedInternal is the operator's exemption, one bit per InternalHeaders
// entry, read from the environment once.
var forwardedInternal = sync.OnceValue(func() uint16 {
	return parseForwardInternalHeaders(os.Getenv(EnvForwardInternalHeaders))
})

func parseForwardInternalHeaders(v string) uint16 {
	var mask uint16
	for name := range strings.SplitSeq(v, ",") {
		if i := internalHeaderIndex(http.CanonicalHeaderKey(strings.TrimSpace(name))); i >= 0 {
			mask |= 1 << i
		}
	}
	return mask
}

// StripInternalHeaders removes every InternalHeaders entry a client sent, in
// the canonical spelling and in the underscore and dot aliases a
// header-folding backend reads as the same name, except those the operator
// exempted. It returns one bit per entry removed, so the caller can count
// them by name without this package knowing how.
//
// A request carrying none of them, which is nearly every request, costs one
// pass over its header keys and allocates nothing.
func StripInternalHeaders(h http.Header) uint16 {
	return stripInternalHeaders(h, forwardedInternal())
}

func stripInternalHeaders(h http.Header, exempt uint16) uint16 {
	var found uint16
	for key := range h {
		// Every entry, and every alias of one, starts with X and is at least
		// as long as the shortest. Most headers fail this and cost nothing more.
		if len(key) < minInternalHeaderLen || (key[0] != 'X' && key[0] != 'x') {
			continue
		}
		i := internalHeaderIndex(key)
		if i < 0 && strings.ContainsAny(key, "_.") {
			i = internalAliasIndex(key)
		}
		if i >= 0 && exempt&(1<<i) == 0 {
			found |= 1 << i
			// Deleting the key being visited is safe during a range.
			delete(h, key)
		}
	}
	return found
}

// internalAliasIndex resolves an underscore or dot spelling to its entry.
func internalAliasIndex(key string) int {
	folded := FoldHeaderName(key)
	for i, name := range InternalHeaders {
		if FoldHeaderName(name) == folded {
			return i
		}
	}
	return -1
}
