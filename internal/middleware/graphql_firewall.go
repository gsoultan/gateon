package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

type GraphQLFirewallConfig struct {
	MaxDepth      int
	MaxComplexity int
	FieldCosts    map[string]int
	FieldClaims   map[string]string // fieldName -> requiredClaim
	Introspection bool              // Allow introspection
}

func GraphQLFirewall(cfg GraphQLFirewallConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			// We need to read the body to parse the GraphQL query
			// In a real implementation, we should use a buffered reader or limit the size
			var body struct {
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
				return
			}

			if body.Query == "" {
				next.ServeHTTP(w, r)
				return
			}

			doc, gerr := parser.ParseQuery(&ast.Source{Input: body.Query})
			if gerr != nil {
				http.Error(w, fmt.Sprintf("GraphQL parse error: %v", gerr), http.StatusBadRequest)
				return
			}

			// 1. Introspection check
			if !cfg.Introspection {
				if isIntrospectionQuery(doc) {
					http.Error(w, "GraphQL introspection is disabled", http.StatusForbidden)
					return
				}
			}

			// 2. Depth check
			depth := calculateDepth(doc)
			if cfg.MaxDepth > 0 && depth > cfg.MaxDepth {
				http.Error(w, fmt.Sprintf("GraphQL query depth %d exceeds limit %d", depth, cfg.MaxDepth), http.StatusForbidden)
				return
			}

			// 3. Complexity check
			complexity := calculateComplexity(doc, cfg.FieldCosts)
			if cfg.MaxComplexity > 0 && complexity > cfg.MaxComplexity {
				http.Error(w, fmt.Sprintf("GraphQL query complexity %d exceeds limit %d", complexity, cfg.MaxComplexity), http.StatusForbidden)
				return
			}

			// 4. Field-level Auth
			if len(cfg.FieldClaims) > 0 {
				if err := checkFieldAuth(doc, r, cfg.FieldClaims); err != nil {
					http.Error(w, err.Error(), http.StatusForbidden)
					return
				}
			}

			// Restore body for the next handler
			// Note: This is a simplified approach. In Gateon, we might want to use a more efficient way to re-inject the body.
			// Since we already decoded it, we can re-encode it or use a custom ReadCloser.
			newBody, _ := json.Marshal(body)
			r.Body = io.NopCloser(strings.NewReader(string(newBody)))
			r.ContentLength = int64(len(newBody))

			next.ServeHTTP(w, r)
		})
	}
}

func isIntrospectionQuery(doc *ast.QueryDocument) bool {
	for _, op := range doc.Operations {
		for _, sel := range op.SelectionSet {
			if field, ok := sel.(*ast.Field); ok {
				if strings.HasPrefix(field.Name, "__") {
					return true
				}
			}
		}
	}
	return false
}

func calculateDepth(doc *ast.QueryDocument) int {
	maxDepth := 0
	for _, op := range doc.Operations {
		d := selectionSetDepth(op.SelectionSet)
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

func selectionSetDepth(ss ast.SelectionSet) int {
	maxSubDepth := 0
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			if len(s.SelectionSet) > 0 {
				d := selectionSetDepth(s.SelectionSet)
				if d > maxSubDepth {
					maxSubDepth = d
				}
			}
		case *ast.InlineFragment:
			d := selectionSetDepth(s.SelectionSet)
			if d > maxSubDepth {
				maxSubDepth = d
			}
		case *ast.FragmentSpread:
			// For simplicity, we don't resolve fragments here.
			// In a full implementation, we should look up the fragment definition.
		}
	}
	return 1 + maxSubDepth
}

func calculateComplexity(doc *ast.QueryDocument, costs map[string]int) int {
	totalComplexity := 0
	for _, op := range doc.Operations {
		totalComplexity += selectionSetComplexity(op.SelectionSet, costs)
	}
	return totalComplexity
}

func selectionSetComplexity(ss ast.SelectionSet, costs map[string]int) int {
	complexity := 0
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			cost := 1
			if c, ok := costs[s.Name]; ok {
				cost = c
			}
			if len(s.SelectionSet) > 0 {
				complexity += cost + selectionSetComplexity(s.SelectionSet, costs)
			} else {
				complexity += cost
			}
		case *ast.InlineFragment:
			complexity += selectionSetComplexity(s.SelectionSet, costs)
		}
	}
	return complexity
}

func checkFieldAuth(doc *ast.QueryDocument, r *http.Request, fieldClaims map[string]string) error {
	// Extract claims from request (assuming auth middleware already ran and put them in context or header)
	// For simplicity, we'll check a header X-Gateon-Claims which could be a JSON or comma-separated list
	claimsStr := r.Header.Get("X-Gateon-Claims")
	claims := make(map[string]bool)
	for _, c := range strings.Split(claimsStr, ",") {
		claims[strings.TrimSpace(c)] = true
	}

	for _, op := range doc.Operations {
		if err := validateFields(op.SelectionSet, claims, fieldClaims); err != nil {
			return err
		}
	}
	return nil
}

func validateFields(ss ast.SelectionSet, userClaims map[string]bool, fieldClaims map[string]string) error {
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			if requiredClaim, ok := fieldClaims[s.Name]; ok {
				if !userClaims[requiredClaim] {
					return fmt.Errorf("access denied for field: %s (requires claim: %s)", s.Name, requiredClaim)
				}
			}
			if len(s.SelectionSet) > 0 {
				if err := validateFields(s.SelectionSet, userClaims, fieldClaims); err != nil {
					return err
				}
			}
		case *ast.InlineFragment:
			if err := validateFields(s.SelectionSet, userClaims, fieldClaims); err != nil {
				return err
			}
		}
	}
	return nil
}
