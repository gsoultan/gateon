// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package redact

import (
	"encoding/base64"
	"strings"
)

// The scanners below each find one shape of credential in a text and append
// the spans to mask. None of them needs the text to be well formed: a body
// cut at a capture limit ends wherever it ends, and a value the cut left
// unterminated is masked to the end.

// quotedMask replaces a JSON value that is not a string, so the result stays
// JSON.
const quotedMask = `"` + Mask + `"`

// jsonSpans masks the value of every JSON member whose name IsCredentialParam.
func jsonSpans(s string, spans []span) []span {
	for i := 0; i < len(s); {
		if s[i] != '"' {
			i++
			continue
		}
		end, closed := stringEnd(s, i)
		if !closed {
			return spans
		}
		colon := skipSpace(s, end)
		if colon >= len(s) || s[colon] != ':' || !IsCredentialParam(s[i+1:end-1]) {
			i = end
			continue
		}
		sp, next := jsonValueSpan(s, skipSpace(s, colon+1))
		if sp.end > sp.start {
			spans = append(spans, sp)
		}
		i = next
	}
	return spans
}

// jsonValueSpan is the span to mask for the JSON value at v, and the offset
// after the value. A string keeps its quotes; anything else becomes a string.
// null, true and false hold no secret and are left as they are.
func jsonValueSpan(s string, v int) (span, int) {
	if v >= len(s) {
		return span{}, len(s)
	}
	switch s[v] {
	case '"':
		end, closed := stringEnd(s, v)
		contentEnd := end
		if closed {
			contentEnd = end - 1
		}
		return span{start: v + 1, end: contentEnd, repl: Mask}, end
	case '{', '[':
		end := compositeEnd(s, v)
		return span{start: v, end: end, repl: quotedMask}, end
	}
	end := v
	for end < len(s) && !strings.ContainsRune(",}] \t\r\n", rune(s[end])) {
		end++
	}
	switch s[v:end] {
	case "null", "true", "false":
		return span{}, end
	}
	return span{start: v, end: end, repl: quotedMask}, end
}

// stringEnd returns the offset just past the JSON string that opens at i, and
// whether it is closed before the end of s.
func stringEnd(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		}
	}
	return len(s), false
}

// compositeEnd returns the offset just past the object or array that opens at
// v, or len(s) when s ends first.
func compositeEnd(s string, v int) int {
	depth := 0
	for j := v; j < len(s); j++ {
		switch s[j] {
		case '"':
			end, closed := stringEnd(s, j)
			if !closed {
				return len(s)
			}
			j = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return len(s)
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

// pairSpans masks the value of every name=value pair whose name
// IsCredentialParam. A value runs to the next separator a form body or a query
// string would have encoded -- '&', ';', whitespace, a quote, '<' or '>' -- or,
// when it opens with a quote, to the matching quote.
func pairSpans(s string, spans []span) []span {
	for i := 0; i < len(s); i++ {
		if s[i] != '=' {
			continue
		}
		start := i
		for start > 0 && isNameByte(s[start-1]) {
			start--
		}
		if start == i || !IsCredentialParam(paramName(s[start:i])) {
			continue
		}
		from, to := pairValue(s, i+1)
		if to > from {
			spans = append(spans, span{start: from, end: to, repl: Mask})
		}
		i = max(i, to-1)
	}
	return spans
}

// pairValue returns where the value that starts at v begins and ends.
func pairValue(s string, v int) (from, to int) {
	if v < len(s) && (s[v] == '"' || s[v] == '\'') {
		end := strings.IndexByte(s[v+1:], s[v])
		if end < 0 {
			return v + 1, len(s)
		}
		return v + 1, v + 1 + end
	}
	end := v
	for end < len(s) && !strings.ContainsRune("&; \t\r\n\"'<>", rune(s[end])) {
		end++
	}
	return v, end
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '.' || c == '[' || c == ']' || c == '%'
}

// multipartSpans masks the content of every multipart/form-data part whose
// Content-Disposition names a credential field: a login form a browser posts
// with FormData is multipart, not urlencoded.
func multipartSpans(s string, spans []span) []span {
	const marker = `name="`
	for i := 0; ; {
		k := strings.Index(s[i:], marker)
		if k < 0 {
			return spans
		}
		k += i
		i = k + len(marker)
		nameEnd := strings.IndexByte(s[i:], '"')
		if nameEnd < 0 {
			return spans
		}
		field := s[i : i+nameEnd]
		i += nameEnd
		if (k > 0 && isNameByte(s[k-1])) || !onDispositionLine(s, k) || !IsCredentialParam(field) {
			continue
		}
		from, to := partContent(s, i)
		if to > from {
			spans = append(spans, span{start: from, end: to, repl: Mask})
			i = to
		}
	}
}

// onDispositionLine reports whether offset k is on a Content-Disposition
// header line, so an HTML <input name="password"> is not taken for a part.
func onDispositionLine(s string, k int) bool {
	lineStart := strings.LastIndexByte(s[:k], '\n') + 1
	return hasPrefixFold(s[lineStart:k], "content-disposition:")
}

// partContent returns the content of the part whose headers continue at i:
// from the blank line ending them to the next boundary line, or to the end.
func partContent(s string, i int) (from, to int) {
	blank := strings.Index(s[i:], "\r\n\r\n")
	skip := 4
	if lf := strings.Index(s[i:], "\n\n"); lf >= 0 && (blank < 0 || lf < blank) {
		blank, skip = lf, 2
	}
	if blank < 0 {
		return 0, 0
	}
	from = i + blank + skip
	to = len(s)
	if b := strings.Index(s[from:], "\n--"); b >= 0 {
		to = from + b
		if to > from && s[to-1] == '\r' {
			to--
		}
	}
	return from, to
}

// headerLineSpans masks the value of every line of s that reads as a
// credential header ("Cookie: sid=...", "X-Api-Key: ..."): a body or a log
// line quoting a request's headers back.
func headerLineSpans(s string, spans []span) []span {
	for start := 0; start < len(s); {
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			end = len(s)
		} else {
			end += start
		}
		line := s[start:end]
		if colon := strings.IndexByte(line, ':'); colon > 0 && isHeaderName(line[:colon]) && IsCredentialHeader(line[:colon]) {
			from := skipBlank(s, start+colon+1)
			to := end
			if to > from && s[to-1] == '\r' {
				to--
			}
			if to > from {
				spans = append(spans, span{start: from, end: to, repl: Mask})
			}
		}
		start = end + 1
	}
	return spans
}

// isHeaderName reports whether s is a plausible header field name: letters,
// digits and '-', so a JSON member ("token": ...) is not taken for a header.
func isHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && s[i] != '-' {
			return false
		}
	}
	return true
}

func skipBlank(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// minBearerLen is the shortest run after "Bearer" taken for a token. Shorter
// than any issued token, long enough that "bearer of" in a sentence is not one.
const minBearerLen = 8

// schemeSpans masks the credentials after the Bearer and Basic authorization
// schemes, wherever a text quotes an Authorization value.
func schemeSpans(s string, spans []span) []span {
	for i := 0; i < len(s); i++ {
		if s[i]|0x20 != 'b' || (i > 0 && isAlnum(s[i-1])) {
			continue
		}
		from, basic, ok := schemeAt(s, i)
		if !ok {
			continue
		}
		to := from
		for to < len(s) && isToken68(s[to]) {
			to++
		}
		if (basic && !isBasicCredential(s[from:to])) || (!basic && to-from < minBearerLen) {
			continue
		}
		spans = append(spans, span{start: from, end: to, repl: Mask})
		i = to - 1
	}
	return spans
}

// schemeAt reports whether a Bearer or Basic scheme name and its separating
// space start at i, which of the two, and where its credentials start.
func schemeAt(s string, i int) (from int, basic, ok bool) {
	switch {
	case hasPrefixFold(s[i:], "bearer"):
		from = i + len("bearer")
	case hasPrefixFold(s[i:], "basic"):
		from, basic = i+len("basic"), true
	default:
		return 0, false, false
	}
	if from >= len(s) || (s[from] != ' ' && s[from] != '\t') {
		return 0, false, false
	}
	return skipSpace(s, from), basic, true
}

// isBasicCredential reports whether a Basic value decodes to user:password.
func isBasicCredential(tok string) bool {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(tok); err == nil {
			return strings.IndexByte(string(b), ':') >= 0
		}
	}
	return false
}

// tokenSpans masks JSON Web Tokens, and what follows a token prefix the gateway
// recognises (gateon_tok_, v4.local. and the other PASETO headers), anywhere
// in a text. The prefix is kept: it says what kind of credential was there.
func tokenSpans(s string, spans []span) []span {
	for i := 0; ; {
		k := strings.Index(s[i:], "eyJ")
		if k < 0 {
			break
		}
		k += i
		i = k + 3
		if k > 0 && isBase64URL(s[k-1]) {
			continue
		}
		if end, ok := jwtEnd(s, k); ok {
			spans = append(spans, span{start: k, end: end, repl: Mask})
			i = end
		}
	}
	for _, p := range tokenPrefixes {
		if strings.ContainsAny(p, "%+") {
			continue // encoded schemes only occur inside a parameter value
		}
		spans = prefixSpans(s, p, spans)
	}
	return spans
}

// jwtEnd returns the end of the JSON Web Token at k: two base64url segments
// each followed by a dot, then the signature (possibly empty).
func jwtEnd(s string, k int) (int, bool) {
	j := k
	for seg := 0; seg < 2; seg++ {
		start := j
		for j < len(s) && isBase64URL(s[j]) {
			j++
		}
		if j-start < 4 || j >= len(s) || s[j] != '.' {
			return 0, false
		}
		j++
	}
	for j < len(s) && isBase64URL(s[j]) {
		j++
	}
	return j, true
}

// prefixSpans masks the token run after every occurrence of prefix in s.
func prefixSpans(s, prefix string, spans []span) []span {
	for i := 0; ; {
		k := indexFold(s[i:], prefix)
		if k < 0 {
			return spans
		}
		from := i + k + len(prefix)
		to := from
		for to < len(s) && (isBase64URL(s[to]) || s[to] == '.') {
			to++
		}
		if to > from {
			spans = append(spans, span{start: from, end: to, repl: Mask})
		}
		i = to
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isBase64URL(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }

// isToken68 reports whether c may appear in an RFC 9110 token68.
func isToken68(c byte) bool {
	return isAlnum(c) || strings.IndexByte("-._~+/=", c) >= 0
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// indexFold is strings.Index without regard to ASCII case.
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}
