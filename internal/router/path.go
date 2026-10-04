// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"path"
	"strings"
)

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

// AmbiguousPath reports whether common backends resolve p to a different
// resource than this router does, so that no normalisation here can make the
// route the gateway chose and the resource the backend serves agree (DP-F8).
//
// Two shapes, both refused rather than rewritten:
//
//   - a dot segment carrying path parameters, "..;" or ".;" (/public/..;/admin).
//     Tomcat and Spring strip ";params" from each segment and then resolve the
//     dots, serving /admin; to this router and to RFC 3986 "..;" is an ordinary
//     segment name, so the request ran /public's chain. Resolving it here would
//     be wrong for every backend that does not strip parameters, and there is
//     no legitimate reason for a client to send one.
//   - a backslash (also %5C, since r.URL.Path is decoded). IIS and ASP.NET treat
//     it as a separator, so /public\..\admin is /admin to them and one segment
//     to everything else. Rewriting it to "/" would change the path for the
//     backends that take it literally.
//
// "/admin;x=1" is not refused: a parameter on an ordinary segment is legal and
// meaningful to JAX-RS and others (see TestSelectRouteLeavesPathParametersAlone).
//
// Runs on every request: one scan, no allocation.
func AmbiguousPath(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			return true
		case ';':
			start := strings.LastIndexByte(p[:i], '/') + 1
			if seg := p[start:i]; seg == "." || seg == ".." {
				return true
			}
		}
	}
	return false
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
