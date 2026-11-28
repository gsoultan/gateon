// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package features

import (
	"math"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// The words a column of categories holds for "anything else" and "nothing".
const (
	valueOther = "other"
	valueNone  = "none"
)

// extensions is the closed list of file extensions a row names. Anything
// else is "other", so a client cannot add a category by inventing a suffix.
var extensions = map[string]bool{
	"php": true, "asp": true, "aspx": true, "jsp": true, "cgi": true, "pl": true,
	"env": true, "git": true, "bak": true, "sql": true, "ini": true, "conf": true,
	"xml": true, "json": true, "js": true, "css": true, "html": true, "png": true,
	"jpg": true, "svg": true, "ico": true, "txt": true, "zip": true, "gz": true,
}

// methods is the closed list of methods a row names.
var methods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

// shape fills the columns that describe the request line and its values.
func shape(set setter, e *corpus.Entry) {
	p, query, _ := strings.Cut(e.Target, "?")
	values := argValues(e.Args, query)
	// Sorted, so that a sample gives the same row whatever order its
	// parameters came out of a map in.
	slices.Sort(values)
	pieces := append([]string{p}, values...)

	set(colMethod, methodValue(e.Method))
	set(colPathDepth, itoa(strings.Count(strings.Trim(p, "/"), "/")+boolInt(strings.Trim(p, "/") != "")))
	set(colPathLength, itoa(len(p)))
	set(colExtension, extensionValue(p))
	set(colArgs, itoa(len(values)))
	set(colHeaders, itoa(len(e.Headers)))

	longest := ""
	for _, v := range values {
		if len(v) > len(longest) {
			longest = v
		}
	}
	set(colLongest, itoa(len(longest)))
	set(colEntropy, ratio(entropy(longest)))
	m := measure(pieces)
	set(colEncoded, ratio(share(3*m.escapes, m.bytes)))
	set(colSymbols, ratio(share(m.symbols, m.bytes)))
	set(colDouble, yesNo(m.double))
	set(colTraversal, yesNo(m.traversal))
	set(colControl, yesNo(m.control))
}

// measures are what shape counts over the path and every value, each
// counted on its own so that two values never join into a pattern neither
// holds.
type measures struct {
	bytes, escapes, symbols    int
	double, traversal, control bool
}

func measure(pieces []string) measures {
	var m measures
	for _, s := range pieces {
		lower := strings.ToLower(s)
		m.bytes += len(s)
		m.escapes += percentEscapes(s)
		m.symbols += symbols(s)
		m.double = m.double || strings.Contains(lower, "%25")
		m.traversal = m.traversal || strings.Contains(s, "../") || strings.Contains(s, `..\`)
		m.control = m.control || hasControl(lower)
	}
	return m
}

// argValues is every parameter value a sample carries: the captured ones,
// and those still in the target, as a hand-written corpus keeps them.
func argValues(args map[string]string, query string) []string {
	values := make([]string, 0, len(args)+strings.Count(query, "&")+1)
	for _, v := range args {
		values = append(values, v)
	}
	if query == "" {
		return values
	}
	for pair := range strings.SplitSeq(query, "&") {
		_, v, _ := strings.Cut(pair, "=")
		values = append(values, v)
	}
	return values
}

func methodValue(m string) string {
	m = strings.ToUpper(m)
	if m == "" {
		return http.MethodGet
	}
	if methods[m] {
		return m
	}
	return valueOther
}

func extensionValue(p string) string {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	switch {
	case ext == "":
		return valueNone
	case extensions[ext]:
		return ext
	}
	return valueOther
}

// percentEscapes counts the %XX escapes in s.
func percentEscapes(s string) int {
	n := 0
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHex(s[i+1]) && isHex(s[i+2]) {
			n++
		}
	}
	return n
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// symbols counts the bytes of s that are neither letters, digits nor the
// separators an ordinary path or value is made of.
func symbols(s string) int {
	n := 0
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '-', c == '_', c == '.', c == ' ':
		default:
			n++
		}
	}
	return n
}

// hasControl reports a control byte, raw or escaped, in s, which is lower
// case.
func hasControl(s string) bool {
	for i := range len(s) {
		if s[i] < ' ' || s[i] == 0x7f {
			return true
		}
	}
	return strings.Contains(s, "%00")
}

// entropy is the Shannon entropy of s in bits per byte, 0 to 8.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func share(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return min(float64(part)/float64(whole), 1)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// agentTools are the user agents of tools rather than browsers. A request
// can claim any user agent it likes, so this is a weak signal and is only
// ever one column among many.
var agentTools = []string{
	"curl", "wget", "python", "go-http-client", "sqlmap", "nikto", "nmap", "masscan",
	"zgrab", "nuclei", "gobuster", "dirbuster", "wpscan", "httpie", "java/", "libwww",
}

// headers fills the columns that come from the request headers.
func headers(set setter, e *corpus.Entry) {
	h := make(http.Header, len(e.Headers))
	for name, value := range e.Headers {
		h.Set(name, value)
	}
	set(colAgent, agentValue(h.Get("User-Agent")))
	set(colAccept, yesNo(h.Get("Accept") == ""))
	set(colContentType, yesNo(h.Get("Content-Type") != ""))
}

func agentValue(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case ua == "":
		return "missing"
	case strings.HasPrefix(ua, "mozilla/"):
		return "browser"
	}
	for _, t := range agentTools {
		if strings.Contains(ua, t) {
			return "tool"
		}
	}
	return valueOther
}
