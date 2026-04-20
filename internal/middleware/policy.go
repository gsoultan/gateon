package middleware

import (
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/gsoultan/gateon/internal/httputil"
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
func Policy(cfg PolicyConfig) (Middleware, error) {
	env, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("auth", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	type compiledRule struct {
		ast     *cel.Ast
		program cel.Program
		msg     string
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
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			data := map[string]any{
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

			for _, cr := range compiledRules {
				out, _, err := cr.program.Eval(data)
				if err != nil {
					httputil.WriteJSONError(w, http.StatusInternalServerError, "Policy evaluation error", err.Error())
					return
				}

				if out.Type() != types.BoolType {
					httputil.WriteJSONError(w, http.StatusInternalServerError, "Policy must return boolean", "")
					return
				}

				if out.Value().(bool) == false {
					msg := cr.msg
					if msg == "" {
						msg = "Access denied by policy"
					}
					httputil.WriteJSONError(w, http.StatusForbidden, msg, "")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func getAuthClaims(r *http.Request) map[string]any {
	if val := r.Context().Value(UserContextKey); val != nil {
		if claims, ok := val.(map[string]any); ok {
			return claims
		}
		// In case it's jwt.MapClaims
		if m, ok := val.(interface{ ToMap() map[string]any }); ok {
			return m.ToMap()
		}
		// Fallback for jwt.MapClaims which is map[string]interface{}
		if m, ok := val.(map[string]interface{}); ok {
			return m
		}
	}
	return make(map[string]any)
}
