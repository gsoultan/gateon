// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import "path"

// NormalizePath resolves "." and ".." segments and collapses repeated slashes,
// returning its input unchanged when there is nothing to resolve.
//
// Route selection walks the path one segment at a time and treats ".." as an
// ordinary segment name, so /public/../admin matches /public. Nothing upstream
// resolved it first: Go's HTTP server leaves r.URL.Path exactly as the client
// sent it, and pkg/proxy joins that same string onto the backend URL, where
// nginx, Apache and most frameworks do resolve it and serve /admin. The route
// that ran was /public's, with /public's middleware chain -- including whatever
// authentication /admin was carrying and /public was not.
//
// Resolving before selection is what makes the route the gateway chose and the
// resource the backend serves the same thing.
//
// Percent-encoded traversal is covered without special handling: r.URL.Path
// holds the decoded path, so %2e%2e%2f has already become ../ by the time this
// sees it.
func NormalizePath(p string) string {
	if !needsNormalizing(p) {
		return p
	}
	if p == "" {
		return "/"
	}

	// Root it before cleaning: path.Clean("../admin") is "../admin", and only a
	// rooted path lets Clean discard the segments that try to climb past it.
	rooted := p
	if rooted[0] != '/' {
		rooted = "/" + rooted
	}
	cleaned := path.Clean(rooted)

	// path.Clean drops a trailing slash, and that slash is meaningful here: a
	// prefix rule and an exact rule can differ by exactly that character.
	if p[len(p)-1] == '/' && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// needsNormalizing reports whether p contains anything to resolve.
//
// This runs on every request, so the answer for an already-clean path -- which
// is nearly all of them -- has to be reached without allocating. A path needs
// work only if it does not start at the root, or if some slash is followed by
// another slash or by a dot; scanning for that is cheaper than cleaning a string
// that was already clean.
func needsNormalizing(p string) bool {
	if p == "" || p[0] != '/' {
		return true
	}
	for i := 0; i < len(p)-1; i++ {
		if p[i] == '/' && (p[i+1] == '/' || p[i+1] == '.') {
			return true
		}
	}
	return false
}
