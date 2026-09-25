// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

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

	var compiledRules []compiledRule
	for _, r := range cfg.Rules {
		ast, iss := env.Compile(r.Expression)
		if iss.Err() != nil {
			return nil, fmt.Errorf("failed to compile expression %q: %w", r.Expression, iss.Err())
		}
		prg, err := env.Program(ast)
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
	out, _, err := cr.program.Eval(data)
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
