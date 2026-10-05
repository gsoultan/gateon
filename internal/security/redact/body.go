// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redact

import (
	"strconv"
	"unicode/utf8"
)

// MaxBodyBytes bounds a request or response body the gateway keeps: what the
// debugger captures, and what a trace or threat stores. 64 KiB, the debugger's
// default, is a whole login form or JSON error many times over; past it a body
// is costing trace storage and webhook bytes, not triage.
const MaxBodyBytes = 64 << 10

// truncatedNote ends a body Body cut at MaxBodyBytes, so that a reader can tell
// a cut body from a short one.
const truncatedNote = "\n[truncated]"

// Body returns a captured body as it may be kept: cut to MaxBodyBytes, with
// every credential Text finds masked.
//
// A body that is not text -- invalid UTF-8, or control bytes a text format does
// not use -- is not kept at all, and a note of its length stands in its place.
// That is a gzip- or brotli-encoded response, a protobuf or gRPC frame, an
// upload: nothing in it can be read to find a credential, so nothing in it can
// be shown to be free of one.
func Body(body string) string {
	if body == "" {
		return ""
	}
	size := len(body)
	cut := size > MaxBodyBytes
	if cut {
		body = body[:MaxBodyBytes]
	}
	// A capture limit, ours or the debugger's, can split the last character.
	body = trimPartialRune(body)
	if !isText(body) {
		return "[" + strconv.Itoa(size) + "-byte non-text body not kept]"
	}
	body = Text(body)
	if cut {
		body += truncatedNote
	}
	return body
}

// trimPartialRune drops an incomplete UTF-8 sequence from the end of s.
func trimPartialRune(s string) string {
	for i := len(s) - 1; i >= 0 && i >= len(s)-utf8.UTFMax; i-- {
		if !utf8.RuneStart(s[i]) {
			continue
		}
		if utf8.FullRuneInString(s[i:]) {
			return s
		}
		return s[:i]
	}
	return s
}

// isText reports whether s reads as text: valid UTF-8 with no control bytes
// but tab, line feed and carriage return.
func isText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return false
		}
	}
	return utf8.ValidString(s)
}

// Text returns s with every credential it can find masked, the names that say
// so kept:
//
//   - a JSON member named like a credential ("password": "...",
//     "access_token": ..., "api_key": {...}): the value, whatever its type;
//   - a line quoting a credential header ("Cookie: sid=..."): the rest of it;
//   - a name=value pair named like one, as in a form body, a query string or a
//     log line quoting either;
//   - a multipart/form-data part named like one;
//   - the credentials after "Bearer" and "Basic" (a Basic value only when it
//     decodes to user:password, so the word in a sentence is left alone);
//   - a JSON Web Token, a gateway API token or a PASETO token anywhere.
//
// It returns s itself, with no allocation, when there is nothing to mask. It
// does not decode, so a credential inside an encoding it does not read -- a
// base64 blob, a percent-encoded JSON document -- is not found.
func Text(s string) string {
	var spans []span
	spans = jsonSpans(s, spans)
	spans = headerLineSpans(s, spans)
	spans = pairSpans(s, spans)
	spans = multipartSpans(s, spans)
	spans = schemeSpans(s, spans)
	spans = tokenSpans(s, spans)
	return apply(s, spans)
}
