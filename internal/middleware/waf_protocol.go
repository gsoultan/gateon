// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"strings"
)

// Protocol enforcement is gateon's now, not the rule engine's.
//
// The OWASP CRS did this with rules 911 and 920 — a method allowlist, a
// content-type allowlist, limits on header names, and checks for duplicated
// framing headers. gwaf deliberately ships none of them: they are properties of
// the HTTP conversation rather than of a payload, and expressing "this header
// appears twice" as a rule that inspects one value at a time never worked well.
// It is why the gRPC and CORS workarounds existed at all.
//
// So these checks live here, ahead of the engine, where they are cheap
// (comparisons against a fixed set, no allocation) and where they can see the
// whole request. What is deliberately *not* reproduced is the CRS
// content-type allowlist, which is what broke gRPC and required the compat
// directives: the engine now inspects binary payloads by extracting printable
// runs, so refusing an unfamiliar content type buys nothing.

// defaultAllowedMethods matches the set the SecLang preamble configured.
//
// It is an allowlist rather than a denylist because the failure modes are not
// symmetric: an unknown method that reaches the origin may be routed somewhere
// no one considered, whereas a rejected one is a visible 405.
var defaultAllowedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
}

// maxHeaderNameLength bounds a header name, replacing CRS rule 1120011.
//
// Names are drawn from a small vocabulary in practice; a long one is either a
// probe or an attempt to exhaust a parser somewhere downstream.
const maxHeaderNameLength = 256

// protocolViolation describes a refused request.
type protocolViolation struct {
	reason string
	status int
}

// checkProtocol enforces the request-level rules the CRS used to.
//
// It returns nil for a conforming request. Ordering is cheapest-first: a method
// comparison is a map lookup, where the duplicate-header checks walk the header
// map.
func checkProtocol(r *http.Request, allowed map[string]bool) *protocolViolation {
	if len(allowed) == 0 {
		allowed = defaultAllowedMethods
	}
	if !allowed[r.Method] {
		return &protocolViolation{
			reason: "method not allowed",
			status: http.StatusMethodNotAllowed,
		}
	}

	// Conflicting framing headers are how request smuggling starts: the proxy
	// and the origin disagree about where one request ends and the next
	// begins. gwaf detects the Content-Length/Transfer-Encoding conflict in the
	// engine, but a *repeated* Content-Length never reaches it, because Go's
	// header map has already joined the values.
	if vs := r.Header.Values("Content-Length"); len(vs) > 1 || (len(vs) == 1 && strings.Contains(vs[0], ",")) {
		return &protocolViolation{
			reason: "multiple Content-Length headers",
			status: http.StatusBadRequest,
		}
	}
	if vs := r.Header.Values("Content-Type"); len(vs) > 1 {
		return &protocolViolation{
			reason: "multiple Content-Type headers",
			status: http.StatusBadRequest,
		}
	}

	for name := range r.Header {
		if len(name) > maxHeaderNameLength {
			return &protocolViolation{
				reason: "header name too long",
				status: http.StatusRequestHeaderFieldsTooLarge,
			}
		}
	}

	return nil
}

// parseAllowedMethods reads the configured method allowlist.
func parseAllowedMethods(csv string) map[string]bool {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	out := make(map[string]bool, 8)
	for _, m := range strings.Split(csv, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			out[m] = true
		}
	}
	return out
}
