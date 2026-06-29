package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

var (
	graphqlQueryCache *lru.ARCCache
	graphqlCacheOnce  sync.Once

	graphqlBufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
)

type GraphQLFirewallConfig struct {
	MaxDepth      int
	MaxComplexity int
	FieldCosts    map[string]int
	FieldClaims   map[string]string // fieldName -> requiredClaim
	Introspection bool              // Allow introspection
}

type queryAnalysis struct {
	depth        int
	complexity   int
	isIntrospect bool
}

func initGraphQLCache() {
	graphqlCacheOnce.Do(func() {
		graphqlQueryCache, _ = lru.NewARC(2048)
	})
}

type pooledReadCloser struct {
	io.Reader
	buf *bytes.Buffer
}

func (prc *pooledReadCloser) Close() error {
	graphqlBufferPool.Put(prc.buf)
	return nil
}

func GraphQLFirewall(cfg GraphQLFirewallConfig) Middleware {
	initGraphQLCache()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			// Use a pooled buffer to read the body once
			buf := graphqlBufferPool.Get().(*bytes.Buffer)
			buf.Reset()

			// Limit body size to avoid OOM
			if _, err := io.Copy(buf, io.LimitReader(r.Body, 10*1024*1024)); err != nil {
				graphqlBufferPool.Put(buf)
				http.Error(w, "Error reading request body", http.StatusInternalServerError)
				return
			}
			r.Body.Close()

			var body struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
				graphqlBufferPool.Put(buf)
				http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
				return
			}

			if body.Query == "" {
				r.Body = &pooledReadCloser{Reader: bytes.NewReader(buf.Bytes()), buf: buf}
				next.ServeHTTP(w, r)
				return
			}

			// Cache lookup for query analysis
			var analysis queryAnalysis
			var found bool
			if graphqlQueryCache != nil {
				if cached, ok := graphqlQueryCache.Get(body.Query); ok {
					analysis = cached.(queryAnalysis)
					found = true
				}
			}

			if !found {
				doc, gerr := parser.ParseQuery(&ast.Source{Input: body.Query})
				if gerr != nil {
					graphqlBufferPool.Put(buf)
					http.Error(w, fmt.Sprintf("GraphQL parse error: %v", gerr), http.StatusBadRequest)
					return
				}

				analysis = queryAnalysis{
					depth:        calculateDepth(doc),
					complexity:   calculateComplexity(doc, cfg.FieldCosts),
					isIntrospect: isIntrospectionQuery(doc),
				}
				if graphqlQueryCache != nil {
					graphqlQueryCache.Add(body.Query, analysis)
				}
			}

			// 1. Introspection check
			if !cfg.Introspection && analysis.isIntrospect {
				graphqlBufferPool.Put(buf)
				http.Error(w, "GraphQL introspection is disabled", http.StatusForbidden)
				return
			}

			// 2. Depth check
			if cfg.MaxDepth > 0 && analysis.depth > cfg.MaxDepth {
				graphqlBufferPool.Put(buf)
				http.Error(w, fmt.Sprintf("GraphQL query depth %d exceeds limit %d", analysis.depth, cfg.MaxDepth), http.StatusForbidden)
				return
			}

			// 3. Complexity check
			if cfg.MaxComplexity > 0 && analysis.complexity > cfg.MaxComplexity {
				graphqlBufferPool.Put(buf)
				http.Error(w, fmt.Sprintf("GraphQL query complexity %d exceeds limit %d", analysis.complexity, cfg.MaxComplexity), http.StatusForbidden)
				return
			}

			// 4. Field-level Auth (This still needs the doc, but we can re-parse or cache parsed doc if needed)
			// For now, we only re-parse if field auth is enabled to keep the common path fast.
			if len(cfg.FieldClaims) > 0 {
				doc, gerr := parser.ParseQuery(&ast.Source{Input: body.Query})
				if gerr == nil {
					if err := checkFieldAuth(doc, r, cfg.FieldClaims); err != nil {
						graphqlBufferPool.Put(buf)
						http.Error(w, err.Error(), http.StatusForbidden)
						return
					}
				}
			}

			// Re-inject body using the pooled buffer
			r.Body = &pooledReadCloser{Reader: bytes.NewReader(buf.Bytes()), buf: buf}
			r.ContentLength = int64(buf.Len())

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
