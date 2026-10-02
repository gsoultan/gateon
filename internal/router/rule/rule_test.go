// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package rule

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// Each refusal names the character where reading stopped and says why, so an
// operator can find a typo in a long rule without guessing.
func TestARuleThatDoesNotParseIsRefusedWithItsPosition(t *testing.T) {
	for _, tc := range []struct {
		rule    string
		pos     int
		message string
	}{
		{"PathPrefix(`/bad", 12, "quote is never closed"},
		{"Host(`internal.example.com`", 28, "expected ) to close Host("},
		{"Hots(`internal.example.com`)", 1, `unknown condition "Hots" (did you mean Host?)`},
		{"PathPrefx(`/admin`)", 1, `unknown condition "PathPrefx" (did you mean PathPrefix?)`},
		{"PathRegex(`^/(admin`)", 11, "regular expression does not compile"},
		{"Host(``)", 6, "Host's value is empty"},
		{"PathPrefix(``)", 12, "PathPrefix(`/`) matches every path"},
		{"   ", 1, "the rule is empty"},
		{"Host(`a`) &&", 13, "the rule ends here"},
		{"Host(`a`) Path(`/x`)", 11, "joined with && or ||"},
		{"Host(`a`) & Path(`/x`)", 11, "joined with && or ||"},
		{"internal.example.com", 1, `unknown condition "internal"`},
		{"Host(`a`, `b`)", 1, "Host(`a`) || Host(`b`)"},
		{"Methods(`GET, POST`)", 9, "each method is its own value"},
		{"Headers(`X-Env`)", 1, "a header name and a value"},
		{"(Host(`a`) || Host(`b`)", 24, "close the parenthesis at character 1"},
		{"L4(`x`)", 4, "L4() takes no values"},
		{"Host(`é`) && Hots(`x`)", 14, "unknown condition"},
	} {
		_, err := Parse(tc.rule)
		var re *Error
		if !errors.As(err, &re) {
			t.Errorf("%q: got %v, want a *rule.Error", tc.rule, err)
			continue
		}
		if re.Pos != tc.pos || !strings.Contains(re.Msg, tc.message) {
			t.Errorf("%q: got %q at %d, want %q at %d", tc.rule, re.Msg, re.Pos, tc.message, tc.pos)
		}
	}
}

// Every shape a shipped caller writes -- the dashboard's rule builder, the
// Kubernetes controller, the unlisted-route detector, the test and e2e
// configs -- still parses.
func TestEveryRuleShapeInUseParses(t *testing.T) {
	for _, src := range []string{
		"PathPrefix(`/`)",
		"Host(`*`)",
		"Host(`*.example.com`)",
		"Host(\"api.example.com\") && PathPrefix(\"/v1\")",
		"Host(`www.example.com`) && Path(`/index.html`) && Methods(`GET`) && Headers(`X-Custom`, `val`)",
		"HostRegexp(`.*\\.example\\.com`) && Path(`/api`)",
		"PathRegex(`^/api/v[0-9]+/`) && Methods(`GET`, `POST`)",
		"Headers(`X-Env`, `prod`) && Headers(\"X-Tier\", \"gold\")",
		"Host(`negate.com`) && !Path(`/secret`)",
		"!Host(`a`) || !!PathPrefix(`/b`) || Methods(\"PUT\")",
		"Path(`/a`) || Path(`/b`)",
		"L4()",
		"Host(`a.example`) && PathPrefix(`/x`) && Headers(`X-Api`, ``)",
	} {
		if _, err := Parse(src); err != nil {
			t.Errorf("%q was refused: %v", src, err)
		}
	}
}

// A run of '!' is folded as it is read, so a rule as long as the API body
// allows parses in one pass and without recursing per '!'.
func TestALongNegationRunParses(t *testing.T) {
	e, err := Parse(strings.Repeat("!", 1<<20-63) + "Host(`a.example.com`)")
	if err != nil {
		t.Fatal(err)
	}
	if e.Match(httptest.NewRequest("GET", "http://a.example.com/", nil), "a.example.com") {
		t.Error("an odd run of '!' did not negate")
	}
}

// Parentheses are bounded, because parsing and evaluation recurse per level.
func TestDeepParenthesesAreRefused(t *testing.T) {
	src := strings.Repeat("(", maxDepth+1) + "Host(`a`)" + strings.Repeat(")", maxDepth+1)
	if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), "nest more than") {
		t.Errorf("got %v, want the nesting refused", err)
	}
	ok := strings.Repeat("(", maxDepth) + "Host(`a`)" + strings.Repeat(")", maxDepth)
	if _, err := Parse(ok); err != nil {
		t.Errorf("%d levels refused: %v", maxDepth, err)
	}
}

func TestHostAndHeadersAreReadFromTheParsedRule(t *testing.T) {
	for _, tc := range []struct {
		rule    string
		host    string
		hasHost bool
	}{
		{"Host(`a.example`) && PathPrefix(`/x`)", "a.example", true},
		{"PathPrefix(`/x`) && Host(`a.example`)", "a.example", true},
		{"Host(`a.example`) || Path(`/x`)", "", false},
		{"Host(`a.example`) || HostRegexp(`^b`)", "", true},
		{"!Host(`a.example`)", "a.example", false},
		{"Path(`/x`)", "", false},
	} {
		e, err := Parse(tc.rule)
		if err != nil {
			t.Fatalf("%q: %v", tc.rule, err)
		}
		if e.Host() != tc.host || e.HasHost() != tc.hasHost {
			t.Errorf("%q: Host %q HasHost %v, want %q %v", tc.rule, e.Host(), e.HasHost(), tc.host, tc.hasHost)
		}
	}
	e, err := Parse("Path(`/x`) && Headers(`x-env`, `prod`) && !Headers(`X-Debug`, `1`)")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.RequiredHeaders(); len(got) != 1 || got["X-Env"] != "prod" {
		t.Errorf("RequiredHeaders = %v, want only X-Env=prod", got)
	}
}

// A CORS preflight for a method the route serves matches it, and skips the
// header conditions a preflight cannot carry -- as the old matcher did.
func TestAPreflightMatchesTheMethodAndHeadersItAsksFor(t *testing.T) {
	e, err := Parse("Methods(`PUT`) && Headers(`X-Env`, `prod`)")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("OPTIONS", "http://a.example/", nil)
	r.Header.Set("Access-Control-Request-Method", "put")
	if !e.Match(r, "a.example") {
		t.Error("a preflight for PUT did not match a PUT route")
	}
	r.Header.Set("Access-Control-Request-Method", "DELETE")
	if e.Match(r, "a.example") {
		t.Error("a preflight for DELETE matched a PUT route")
	}
}
