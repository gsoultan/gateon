// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPolicyBoundsEvaluationCost: a CEL policy rule reads request.query, whose
// size the client chooses, so a nested comprehension over it is work an
// attacker scales with one request. Without a runtime cost ceiling that
// evaluation runs to completion, burning CPU a 2-core host cannot spare
// (CLAUDE.md: "the WAF must never be the outage"). With the ceiling the
// evaluation exits over budget and the request is refused, so the cost of a
// hostile request is bounded, not paid.
//
// Root cause: env.Program was built without cel.CostLimit, leaving policy
// evaluation unbounded in CPU against attacker-sized inputs.
//
// The rule compares every query value to every other (O(n^2)); all values are
// identical, so absent a cost limit the rule evaluates to true and the request
// is ALLOWED (200) -- the pre-fix behaviour this asserts against. A tiny
// GATEON_POLICY_CEL_COST_LIMIT makes the test deterministic without depending
// on the exact cost model.
func TestPolicyBoundsEvaluationCost(t *testing.T) {
	t.Setenv(policyCostLimitEnv, "10000")

	mw, err := Policy(PolicyConfig{Rules: []PolicyRule{{
		// Benign-looking: "every tag equals every other tag". The point is only
		// that it is a comprehension over attacker-controlled request.query.
		Expression: `request.query["tag"].all(a, request.query["tag"].all(b, a == b))`,
		Message:    "tags must match",
	}}})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	reqWithTags := func(n int) *http.Request {
		vals := make([]string, n)
		for i := range vals {
			vals[i] = "x" // identical, so the rule's verdict is "allow" if it ever finishes
		}
		q := url.Values{"tag": vals}
		r := httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil)
		return r
	}

	t.Run("hostile input is refused over budget, not evaluated to completion", func(t *testing.T) {
		var reached bool
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, reqWithTags(2000))

		if reached {
			t.Error("a request with 2000 query values ran the policy comprehension " +
				"to completion; CEL evaluation is unbounded in CPU (no cel.CostLimit)")
		}
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d (an over-budget evaluation is an unknown "+
				"verdict and must refuse)", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("benign input still passes under the same ceiling", func(t *testing.T) {
		var reached bool
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, reqWithTags(3))

		if !reached {
			t.Errorf("a 3-value request was refused with %d; the cost bound must only "+
				"affect evaluations that are actually expensive, not deny everything", rr.Code)
		}
	})
}

// TestPolicyCostLimitNeverSilentlyDisabled: a missing, malformed or zero
// override must fall back to the default ceiling, never to "unbounded". An
// unbounded policy evaluator is the one state the bound exists to prevent.
func TestPolicyCostLimitNeverSilentlyDisabled(t *testing.T) {
	cases := map[string]string{
		"unset":    "",
		"zero":     "0",
		"garbage":  "not-a-number",
		"negative": "-1",
		"spaces":   "   ",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			if strings.TrimSpace(val) == "" {
				t.Setenv(policyCostLimitEnv, "") // unset/empty
			} else {
				t.Setenv(policyCostLimitEnv, val)
			}
			if got := policyCostLimit(); got != defaultPolicyCostLimit {
				t.Errorf("policyCostLimit() = %d, want default %d: a bad override must "+
					"never disable the bound", got, defaultPolicyCostLimit)
			}
		})
	}

	t.Run("valid override is honoured", func(t *testing.T) {
		t.Setenv(policyCostLimitEnv, "500000")
		if got := policyCostLimit(); got != 500000 {
			t.Errorf("policyCostLimit() = %d, want 500000", got)
		}
	})
}
