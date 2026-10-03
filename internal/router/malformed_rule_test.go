// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// malformedRules are rules the matcher cannot read in full. Each used to parse
// to an empty matcher, which matches every request, so a typo on one route took
// the entrypoint's traffic from the routes it did not describe -- and with it
// their auth and WAF (ADR 0043). The first four are the review's probe; the
// rest are the same defect in shapes the old parser also read as "no
// condition": a regex that does not compile, an empty argument, a rule of
// whitespace, a condition the parser silently dropped, and a bare word.
var malformedRules = []string{
	"PathPrefix(`/bad",
	"Host(`internal.example.com`",
	"Hots(`internal.example.com`)",
	"PathPrefx(`/admin`)",
	"PathRegex(`^/(admin`)",
	"HostRegexp(`[`)",
	"Host(``)",
	"PathPrefix(``)",
	"   ",
	"Host(`internal.example.com`) &&",
	"internal.example.com",
	"Host(`internal.example.com`) Path(`/x`)",
}

// A stored rule that does not parse -- an old database, a routes file written
// by hand -- must match nothing, not everything.
func TestAStoredRuleThatDoesNotParseMatchesNothing(t *testing.T) {
	for _, rule := range malformedRules {
		t.Run(rule, func(t *testing.T) {
			bad := &gateonv1.Route{Id: "typo", Rule: rule, Priority: 100}
			good := &gateonv1.Route{Id: "shop", Rule: "PathPrefix(`/shop`)"}
			r := httptest.NewRequest("GET", "http://www.public.example/shop/cart", nil)
			if GetMatcher(rule).Match(r) {
				t.Errorf("rule %q matched GET www.public.example/shop/cart", rule)
			}
			if got := SelectRouteFromSlice(r, []*gateonv1.Route{bad, good}); got == nil || got.Id != "shop" {
				t.Errorf("rule %q took the request from the route that describes it: selected %v", rule, got)
			}
		})
	}
}

var loggedRuleSeq atomic.Int64

// A stored rule that does not parse is logged when the router first meets it,
// and only then: the matcher is cached, so the next request costs a map load,
// not a log line.
func TestAStoredRuleThatDoesNotParseIsLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	prevShim, prevDefault := logger.L, slog.Default()
	logger.L = &logger.SlogShim{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() {
		logger.L = prevShim
		slog.SetDefault(prevDefault)
	})

	// Unique per run: the cache outlives a test under -count.
	rule := fmt.Sprintf("Hots(`once-%d.example`)", loggedRuleSeq.Add(1))
	routes := []*gateonv1.Route{{Id: "typo", Rule: rule}}
	for range 3 {
		SelectRouteFromSlice(httptest.NewRequest("GET", "http://a.example/", nil), routes)
		_ = HostFromRule(rule)
	}
	if n := strings.Count(buf.String(), "route rule does not parse"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "did you mean Host?") {
		t.Errorf("the log line does not say why:\n%s", buf.String())
	}
}

// A rule that the old parser read only in part is now read in full. Each of
// these used to lose a condition: the second Path, the negated exclusion, or
// the Host past the first '||' inside a group.
func TestEveryConditionOfARuleIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		rule, url string
		want      bool
	}{
		{"PathPrefix(`/api`) && !PathPrefix(`/api/admin`)", "http://a.example/api/admin/users", false},
		{"PathPrefix(`/api`) && !PathPrefix(`/api/admin`)", "http://a.example/api/users", true},
		{"Host(`a.example`) && Host(`b.example`)", "http://a.example/", false},
		{"(Host(`a.example`) || Host(`b.example`)) && Path(`/x`)", "http://a.example/y", false},
		{"(Host(`a.example`) || Host(`b.example`)) && Path(`/x`)", "http://b.example/x", true},
		{"!Path(`/private`) && Host(`a.example`)", "http://b.example/public", false},
		{"!Path(`/private`) && Host(`a.example`)", "http://a.example/public", true},
		{"Methods(`GET`,`POST`)", "http://a.example/", true},
		{"PathRegex(`^/api/(v1||v2)/`)", "http://a.example/api/v2/x", true},
	} {
		r := httptest.NewRequest("GET", tc.url, nil)
		if got := GetMatcher(tc.rule).Match(r); got != tc.want {
			t.Errorf("%q on %s: matched %v, want %v", tc.rule, tc.url, got, tc.want)
		}
	}
}
