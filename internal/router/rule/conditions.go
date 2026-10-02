// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package rule

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// conditions are the names a rule may use, in the order an error lists them.
// L4() is what the dashboard writes for a TCP or UDP route, whose traffic is
// chosen by entrypoint and not by rule.
var conditions = []string{"Host", "HostRegexp", "Path", "PathPrefix", "PathRegex", "Methods", "Headers", "L4"}

func isCondition(name string) bool {
	for _, c := range conditions {
		if c == name {
			return true
		}
	}
	return false
}

// unknownCondition names the closest known condition when there is one, since
// the usual cause is a typo.
func unknownCondition(name string) string {
	msg := fmt.Sprintf("unknown condition %q", name)
	if s := closest(name); s != "" {
		msg += fmt.Sprintf(" (did you mean %s?)", s)
	}
	return msg + "; the conditions are Host, HostRegexp, Path, PathPrefix, PathRegex, Methods and Headers"
}

// closest is the known condition within two edits of name, ignoring case.
func closest(name string) string {
	best, bestDist := "", 3
	for _, c := range conditions {
		if d := editDistance(strings.ToLower(name), strings.ToLower(c)); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between two short names.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// badValue is why a condition's values were refused: arg is the index of the
// value at fault, or -1 when the fault is the condition as a whole.
type badValue struct {
	arg int
	msg string
}

// build makes the condition name from its values, or says why it cannot.
// Every refusal here is a value the old parser silently read as "no
// condition": an empty one, or a regular expression that does not compile.
func build(name string, args []value) (node, *badValue) {
	switch name {
	case "Host":
		return single(mHost, name, args, "a host name, such as Host(`example.com`); for several hosts write Host(`a`) || Host(`b`)")
	case "Path":
		return single(mPath, name, args, "a path, such as Path(`/health`)")
	case "PathPrefix":
		return single(mPathPrefix, name, args, "a path prefix, such as PathPrefix(`/api`); PathPrefix(`/`) matches every path")
	case "HostRegexp":
		return regex(mHostRegexp, name, args)
	case "PathRegex":
		return regex(mPathRegex, name, args)
	case "Methods":
		return buildMethods(args)
	case "Headers":
		return buildHeaders(args)
	}
	if len(args) > 0 {
		return node{}, &badValue{arg: 0, msg: "L4() takes no values"}
	}
	return node{kind: mL4}, nil
}

// single is a condition of exactly one non-empty value.
func single(k kind, name string, args []value, want string) (node, *badValue) {
	if len(args) != 1 {
		return node{}, &badValue{arg: -1, msg: fmt.Sprintf("%s takes one value: %s", name, want)}
	}
	if args[0].text == "" {
		return node{}, &badValue{arg: 0, msg: fmt.Sprintf("%s's value is empty; it needs %s", name, want)}
	}
	return node{kind: k, value: args[0].text}, nil
}

func regex(k kind, name string, args []value) (node, *badValue) {
	n, bad := single(k, name, args, "a regular expression, such as "+name+"(`^/api/v[0-9]+/`)")
	if bad != nil {
		return n, bad
	}
	re, err := regexp.Compile(n.value)
	if err != nil {
		return node{}, &badValue{arg: 0, msg: fmt.Sprintf("%s's regular expression does not compile: %v", name, err)}
	}
	n.re = re
	return n, nil
}

func buildMethods(args []value) (node, *badValue) {
	if len(args) == 0 {
		return node{}, &badValue{arg: -1, msg: "Methods takes one or more methods, such as Methods(`GET`, `POST`)"}
	}
	n := node{kind: mMethods, methods: make([]string, 0, len(args))}
	for i, a := range args {
		if !isToken(a.text) {
			return node{}, &badValue{arg: i, msg: fmt.Sprintf("%q is not a method; each method is its own value, "+
				"such as Methods(`GET`, `POST`)", a.text)}
		}
		n.methods = append(n.methods, strings.ToUpper(a.text))
	}
	return n, nil
}

func buildHeaders(args []value) (node, *badValue) {
	if len(args) != 2 {
		return node{}, &badValue{arg: -1, msg: "Headers takes a header name and a value, such as Headers(`X-Env`, `prod`)"}
	}
	if !isToken(args[0].text) {
		return node{}, &badValue{arg: 0, msg: fmt.Sprintf("%q is not a header name", args[0].text)}
	}
	return node{kind: mHeaders, value: http.CanonicalHeaderKey(args[0].text), value2: args[1].text}, nil
}

// isToken reports whether s is a non-empty RFC 9110 token, the syntax of both a
// method and a header name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isIdentByte(c) || strings.IndexByte("!#$%&'*+-.^`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}
