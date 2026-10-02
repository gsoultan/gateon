// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package rule parses and evaluates a route's rule, such as
// Host(`api.example.com`) && PathPrefix(`/v1`).
//
// There is one parser. The route save path uses it to refuse a rule and the
// router uses it to evaluate one, so a rule the gateway accepted is exactly the
// rule it runs, and a rule it cannot read is refused rather than read in part
// (ADR 0043). The parser it replaces looked for each condition by substring and
// ignored whatever it did not recognise; a rule it could not read at all became
// a matcher with no condition, which matches every request.
//
// The grammar:
//
//	expr    = and { "||" and }
//	and     = unary { "&&" unary }
//	unary   = { "!" } primary
//	primary = "(" expr ")" | name "(" [ value { "," value } ] ")"
//	value   = "`" text "`" | `"` text `"`
//
// "!" binds tighter than "&&", which binds tighter than "||". A value is taken
// literally, with no escapes: one that must contain a backtick is written in
// double quotes, and the reverse.
package rule

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
)

// kind is what a node of a parsed rule does.
type kind uint8

const (
	opAnd kind = iota
	opOr
	opNot
	mHost
	mHostRegexp
	mPath
	mPathPrefix
	mPathRegex
	mMethods
	mHeaders
	mL4
)

// node is one operator or condition of a parsed rule.
type node struct {
	kind     kind
	children []node
	value    string // host, path, prefix, or header name
	value2   string // header value
	re       *regexp.Regexp
	methods  []string
}

// Expr is a parsed rule. It is immutable and safe for concurrent use.
type Expr struct {
	root node
}

// Error says where a rule stops being readable and why.
type Error struct {
	// Pos is the 1-based character position in the rule.
	Pos int
	Msg string
}

func (e *Error) Error() string {
	return fmt.Sprintf("at character %d: %s", e.Pos, e.Msg)
}

// Match reports whether r satisfies the rule. host is r's host without its
// port, as the router resolved it once for the request.
func (e *Expr) Match(r *http.Request, host string) bool {
	return e.root.eval(r, host)
}

func (n *node) eval(r *http.Request, host string) bool {
	switch n.kind {
	case opAnd:
		for i := range n.children {
			if !n.children[i].eval(r, host) {
				return false
			}
		}
		return true
	case opOr:
		for i := range n.children {
			if n.children[i].eval(r, host) {
				return true
			}
		}
		return false
	case opNot:
		return !n.children[0].eval(r, host)
	}
	return n.evalCondition(r, host)
}

// evalCondition evaluates a node that is a condition rather than an operator.
func (n *node) evalCondition(r *http.Request, host string) bool {
	switch n.kind {
	case mHost:
		return config.HostMatches(n.value, host)
	case mHostRegexp:
		return n.re.MatchString(host)
	case mPath:
		return r.URL.Path == n.value
	case mPathPrefix:
		return strings.HasPrefix(r.URL.Path, n.value)
	case mPathRegex:
		return n.re.MatchString(r.URL.Path)
	case mMethods:
		return n.matchMethod(r)
	case mHeaders:
		return n.matchHeader(r)
	case mL4:
		return true
	}
	return false
}

// matchMethod accepts a CORS preflight for a method the route serves: the
// browser sends OPTIONS and names the real method in
// Access-Control-Request-Method.
func (n *node) matchMethod(r *http.Request) bool {
	if slices.Contains(n.methods, r.Method) {
		return true
	}
	if r.Method != http.MethodOptions {
		return false
	}
	want := r.Header.Get("Access-Control-Request-Method")
	if want == "" {
		return false
	}
	for _, m := range n.methods {
		if strings.EqualFold(m, want) {
			return true
		}
	}
	return false
}

// matchHeader skips the check on a CORS preflight, which does not carry the
// request's own headers.
func (n *node) matchHeader(r *http.Request) bool {
	if values := r.Header[n.value]; len(values) > 0 && values[0] == n.value2 {
		return true
	}
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// Host is the host a rule names, for choosing a certificate by SNI: the first
// Host() of a rule that is one condition or a conjunction of them, and "" for
// any other rule.
func (e *Expr) Host() string {
	return firstHost(&e.root)
}

func firstHost(n *node) string {
	switch n.kind {
	case mHost:
		return n.value
	case opNot:
		return firstHost(&n.children[0])
	case opAnd:
		for i := range n.children {
			if h := firstHost(&n.children[i]); h != "" {
				return h
			}
		}
	}
	return ""
}

// HasHost reports whether every request the rule matches is held to a host
// condition: a Host() or HostRegexp() that is not negated, on every branch
// of an "||" that could match.
func (e *Expr) HasHost() bool {
	return hasHost(&e.root)
}

func hasHost(n *node) bool {
	switch n.kind {
	case mHost, mHostRegexp:
		return true
	case opAnd:
		return slices.ContainsFunc(n.children, func(c node) bool { return hasHost(&c) })
	case opOr:
		return len(n.children) > 0 && !slices.ContainsFunc(n.children, func(c node) bool { return !hasHost(&c) })
	}
	return false
}

// RequiredHeaders are the headers, by canonical name, that every match must
// carry with the given value.
func (e *Expr) RequiredHeaders() map[string]string {
	out := map[string]string{}
	collectHeaders(&e.root, out)
	return out
}

func collectHeaders(n *node, out map[string]string) {
	switch n.kind {
	case mHeaders:
		out[n.value] = n.value2
	case opAnd:
		for i := range n.children {
			collectHeaders(&n.children[i], out)
		}
	}
}
