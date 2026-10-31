// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

const (
	// policyCostLimitEnv overrides the CEL runtime cost ceiling applied to each
	// rule evaluation. See policyCostLimit.
	policyCostLimitEnv = "GATEON_POLICY_CEL_COST_LIMIT"
	// defaultPolicyCostLimit bounds the CPU a single policy rule may spend on a
	// single request. CEL "cost" is an operation count that tracks CPU (not
	// memory): a rule that reads request.query or request.header -- collections
	// whose size the client chooses -- can otherwise be amplified without limit
	// by one request carrying thousands of values into a comprehension, and a
	// nested comprehension makes that quadratic. Hitting the ceiling exits the
	// evaluation with a "cost limit exceeded" error, which evalPolicyRule
	// already treats as an unknown verdict and refuses, so the cost of a hostile
	// request is bounded rather than paid. A benign rule costs on the order of
	// hundreds of units, far below this. CLAUDE.md: "the WAF must never be the
	// outage"; on a 2-core host one request must not be able to burn a core.
	defaultPolicyCostLimit uint64 = 1_000_000
	// policyInterruptCheckFrequency is how many comprehension iterations run
	// between context-cancellation checks during ContextEval, so a request whose
	// deadline fires mid-evaluation is abandoned rather than run to completion.
	// The cost limit is the hard CPU bound; this makes a long-but-under-budget
	// evaluation honour the request's own deadline as well.
	policyInterruptCheckFrequency uint = 256
)

// policyCostLimit returns the per-rule CEL runtime cost ceiling, overridable
// via GATEON_POLICY_CEL_COST_LIMIT. A missing, malformed or zero value falls
// back to the default rather than disabling the bound: an unbounded policy
// evaluator is the one state this must never silently enter.
func policyCostLimit() uint64 {
	if v := strings.TrimSpace(os.Getenv(policyCostLimitEnv)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultPolicyCostLimit
}

// PolicyRule defines a single CEL-based policy rule.
type PolicyRule struct {
	Expression string `json:"expression"`
	Message    string `json:"message"`
}

// PolicyConfig configures the policy middleware.
type PolicyConfig struct {
	Rules []PolicyRule `json:"rules"`
}

// Policy returns a middleware that evaluates CEL expressions against the request and auth context.
// compiledRule is one policy expression, compiled once when the route is
// built. Package-scoped rather than local to Policy so the evaluation of a
// single rule can be a function of its own.
type compiledRule struct {
	ast     *cel.Ast
	program cel.Program
	msg     string
}

func Policy(cfg PolicyConfig) (kind.Middleware, error) {
	env, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("auth", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	costLimit := policyCostLimit()

	var compiledRules []compiledRule
	for _, r := range cfg.Rules {
		ast, iss := env.Compile(r.Expression)
		if iss.Err() != nil {
			return nil, fmt.Errorf("failed to compile expression %q: %w", r.Expression, iss.Err())
		}
		// CostLimit bounds the CPU this rule can spend on one request
		// regardless of input size (the error it raises on overrun is handled
		// as a refusal in evalPolicyRule); InterruptCheckFrequency makes a
		// ContextEval honour the request deadline mid-comprehension.
		prg, err := env.Program(ast,
			cel.CostLimit(costLimit),
			cel.InterruptCheckFrequency(policyInterruptCheckFrequency),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create program for %q: %w", r.Expression, err)
		}
		compiledRules = append(compiledRules, compiledRule{
			ast:     ast,
			program: prg,
			msg:     r.Message,
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			servePolicy(compiledRules, next, w, r)
		})
	}, nil
}

// policyInput builds the CEL activation for one request.
func policyInput(r *http.Request) map[string]any {
	return map[string]any{
		"request": map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"host":   r.Host,
			"query":  r.URL.Query(),
			// Headers could be large, maybe just a few?
			// For now, include them all for "production ready" completeness.
			"header": r.Header,
		},
		"auth": getAuthClaims(r),
	}
}

func servePolicy(rules []compiledRule, next http.Handler, w http.ResponseWriter, r *http.Request) {
	// No CORS-preflight exemption; see kind.IsCorsPreflight. A policy rule that
	// denies is a deny decision, so naming a preflight must not skip it.
	data := policyInput(r)
	for _, cr := range rules {
		if !evalPolicyRule(cr, data, w, r) {
			return
		}
	}

	next.ServeHTTP(w, r)
}

// evalPolicyRule reports whether the request may continue past this rule. It
// writes its own refusal, so every path that is not a clear allow denies: an
// expression that fails to evaluate is a policy whose verdict is unknown, and
// unknown is not permission.
func evalPolicyRule(cr compiledRule, data map[string]any, w http.ResponseWriter, r *http.Request) bool {
	// ContextEval, not Eval: the request's deadline (with the program's
	// InterruptCheckFrequency) can cut off a runaway evaluation, and the cost
	// limit the program carries still applies regardless of the context.
	out, _, err := cr.program.ContextEval(r.Context(), data)
	if err != nil {
		// Logged, not returned: the error names the keys the rule reads and
		// how, and it used to go to the client in the response body.
		logger.L.LogWarn("policy rule could not be evaluated; refusing the request",
			"path", r.URL.Path, "error", err)
		httputil.WriteJSONError(w, http.StatusInternalServerError, "Policy evaluation error", "")
		return false
	}

	// Comma-ok rather than a bare assertion: a rule whose result is not a bool
	// must refuse, and a bare assertion would panic on the request goroutine
	// instead -- the CEL type check above is a second opinion, not a guarantee
	// about the concrete Go value behind it.
	allowed, ok := out.Value().(bool)
	if out.Type() != types.BoolType || !ok {
		httputil.WriteJSONError(w, http.StatusInternalServerError, "Policy must return boolean", "")
		return false
	}

	if !allowed {
		msg := cr.msg
		if msg == "" {
			msg = "Access denied by policy"
		}
		httputil.WriteJSONError(w, http.StatusForbidden, msg, "")
		return false
	}
	return true
}

// getAuthClaims returns the verified claims the auth middleware stored, as a
// plain map. auth.ToMap handles the plain map the introspection validator stores,
// the named jwt.MapClaims the JWT validator stores, and anything with a auth.ToMap
// method. A direct assertion to map[string]any does not match the named type,
// which left every policy over `auth` blind to JWT claims.
func getAuthClaims(r *http.Request) map[string]any {
	return auth.ToMap(r.Context().Value(auth.UserContextKey))
}
