// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
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

// maxCachedQueryBytes bounds what may become a cache key. The ARC cache holds
// 2048 entries and the key is the query text itself, so without a per-key cap
// the bound is 2048 x the body limit.
const maxCachedQueryBytes = 8 << 10

// fragmentIndex resolves fragment spreads during a walk. Every check below
// (introspection, depth, complexity, field auth) used to skip FragmentSpread,
// so `{ ...F } fragment F on Query { ... }` hid whatever F held from all four.
// open tracks the spreads currently being walked, so a cyclic fragment --
// invalid GraphQL that the parser still accepts -- terminates instead of
// recursing until the stack is gone.
type fragmentIndex struct {
	defs map[string]*ast.FragmentDefinition
	open map[string]bool
}

func newFragmentIndex(doc *ast.QueryDocument) *fragmentIndex {
	defs := make(map[string]*ast.FragmentDefinition, len(doc.Fragments))
	for _, f := range doc.Fragments {
		defs[f.Name] = f
	}
	return &fragmentIndex{defs: defs, open: make(map[string]bool, len(defs))}
}

// enter returns the named fragment's selections and a release func, or a nil
// func when the fragment is unknown or already open (a cycle).
func (fi *fragmentIndex) enter(name string) (ast.SelectionSet, func()) {
	def, ok := fi.defs[name]
	if !ok || fi.open[name] {
		return nil, nil
	}
	fi.open[name] = true
	return def.SelectionSet, func() { delete(fi.open, name) }
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

// maxGraphQLBodyBytes caps what the firewall will read before deciding. A
// GraphQL body is client-chosen text, so without a cap "read the query" means
// "hold whatever arrives".
const maxGraphQLBodyBytes = 10 * 1024 * 1024

func GraphQLFirewall(cfg GraphQLFirewallConfig) kind.Middleware {
	initGraphQLCache()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveGraphQLFirewall(cfg, next, w, r)
		})
	}
}

// graphQLGETAllowed applies the same four limits to a query carried in the
// URL. A GET with no query parameter is not a GraphQL request and costs
// nothing.
func graphQLGETAllowed(cfg GraphQLFirewallConfig, w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query().Get("query")
	if query == "" {
		return true
	}
	analysis, ok := analyseGraphQLQuery(query, cfg, w)
	if !ok {
		return false
	}
	return graphQLQueryAllowed(analysis, query, cfg, r, w)
}

func serveGraphQLFirewall(cfg GraphQLFirewallConfig, next http.Handler, w http.ResponseWriter, r *http.Request) {
	// GET carries the query in the URL, which Apollo Server, gqlgen,
	// graphql-go and Hasura all accept. Skipping it meant
	// `GET /graphql?query={__schema{types{name}}}` walked past the
	// introspection block, the depth limit, the complexity limit and
	// field-level claim auth -- every check this middleware performs, chosen
	// by the client picking a method.
	if r.Method == http.MethodGet {
		if !graphQLGETAllowed(cfg, w, r) {
			return
		}
		next.ServeHTTP(w, r)
		return
	}

	if r.Method != http.MethodPost {
		next.ServeHTTP(w, r)
		return
	}

	// Use a pooled buffer to read the body once.
	buf := graphqlBufferPool.Get().(*bytes.Buffer)
	buf.Reset()

	// The buffer is handed to pooledReadCloser only when the request is
	// forwarded; every refusal returns it here instead. This used to be a
	// Put before each of six http.Error calls, which is six chances to forget
	// one -- and a forgotten Put is a pool that quietly stops being a pool.
	forwarded := false
	defer func() {
		if !forwarded {
			graphqlBufferPool.Put(buf)
		}
	}()

	query, ok := readGraphQLQuery(buf, w, r)
	if !ok {
		return
	}

	if query != "" {
		analysis, ok := analyseGraphQLQuery(query, cfg, w)
		if !ok {
			return
		}
		if !graphQLQueryAllowed(analysis, query, cfg, r, w) {
			return
		}
		r.ContentLength = int64(buf.Len())
	}

	r.Body = &pooledReadCloser{Reader: bytes.NewReader(buf.Bytes()), buf: buf}
	forwarded = true
	next.ServeHTTP(w, r)
}

// readGraphQLQuery reads the body into buf and returns the query it carries.
// A body that is not JSON, or cannot be read, is refused: the firewall cannot
// vouch for a document it could not parse, and forwarding it would mean the
// limits below never applied.
func readGraphQLQuery(buf *bytes.Buffer, w http.ResponseWriter, r *http.Request) (string, bool) {
	if _, err := io.Copy(buf, io.LimitReader(r.Body, maxGraphQLBodyBytes)); err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return "", false
	}
	_ = r.Body.Close()

	var body struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(buf.Bytes(), &body); err != nil {
		http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
		return "", false
	}
	return body.Query, true
}

// analyseGraphQLQuery returns the depth, complexity and introspection verdict
// for a query, from cache when possible.
func analyseGraphQLQuery(query string, cfg GraphQLFirewallConfig, w http.ResponseWriter) (queryAnalysis, bool) {
	if graphqlQueryCache != nil {
		if cached, ok := graphqlQueryCache.Get(query); ok {
			if analysis, ok := cached.(queryAnalysis); ok {
				return analysis, true
			}
		}
	}

	doc, gerr := parser.ParseQuery(&ast.Source{Input: query})
	if gerr != nil {
		http.Error(w, fmt.Sprintf("GraphQL parse error: %v", gerr), http.StatusBadRequest)
		return queryAnalysis{}, false
	}

	analysis := queryAnalysis{
		depth:        calculateDepth(doc),
		complexity:   calculateComplexity(doc, cfg.FieldCosts),
		isIntrospect: isIntrospectionQuery(doc),
	}
	// The cache key is the whole query text, which the client
	// chooses and which the body limit lets reach 10 MiB. Caching
	// those filled 2048 slots with attacker-sized keys; a query
	// this long is not one a client repeats, so it is analysed
	// each time instead of retained.
	if graphqlQueryCache != nil && len(query) <= maxCachedQueryBytes {
		graphqlQueryCache.Add(query, analysis)
	}
	return analysis, true
}

// graphQLQueryAllowed applies the four limits and writes its own refusal.
func graphQLQueryAllowed(analysis queryAnalysis, query string, cfg GraphQLFirewallConfig, r *http.Request, w http.ResponseWriter) bool {
	// 1. Introspection check
	if !cfg.Introspection && analysis.isIntrospect {
		http.Error(w, "GraphQL introspection is disabled", http.StatusForbidden)
		return false
	}

	// 2. Depth check
	if cfg.MaxDepth > 0 && analysis.depth > cfg.MaxDepth {
		http.Error(w, fmt.Sprintf("GraphQL query depth %d exceeds limit %d", analysis.depth, cfg.MaxDepth), http.StatusForbidden)
		return false
	}

	// 3. Complexity check
	if cfg.MaxComplexity > 0 && analysis.complexity > cfg.MaxComplexity {
		http.Error(w, fmt.Sprintf("GraphQL query complexity %d exceeds limit %d", analysis.complexity, cfg.MaxComplexity), http.StatusForbidden)
		return false
	}

	// 4. Field-level Auth (This still needs the doc, but we can re-parse or cache parsed doc if needed)
	// For now, we only re-parse if field auth is enabled to keep the common path fast.
	if len(cfg.FieldClaims) > 0 {
		doc, gerr := parser.ParseQuery(&ast.Source{Input: query})
		if gerr == nil {
			if err := checkFieldAuth(doc, r, cfg.FieldClaims); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return false
			}
		}
	}
	return true
}

func isIntrospectionQuery(doc *ast.QueryDocument) bool {
	fi := newFragmentIndex(doc)
	for _, op := range doc.Operations {
		if fi.introspects(op.SelectionSet) {
			return true
		}
	}
	return false
}

// introspects reports whether the effective top level of ss selects an
// introspection field, looking through fragments rather than past them.
func (fi *fragmentIndex) introspects(ss ast.SelectionSet) bool {
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			if strings.HasPrefix(s.Name, "__") {
				return true
			}
		case *ast.InlineFragment:
			if fi.introspects(s.SelectionSet) {
				return true
			}
		case *ast.FragmentSpread:
			inner, release := fi.enter(s.Name)
			if release == nil {
				continue
			}
			hit := fi.introspects(inner)
			release()
			if hit {
				return true
			}
		}
	}
	return false
}

func calculateDepth(doc *ast.QueryDocument) int {
	fi := newFragmentIndex(doc)
	maxDepth := 0
	for _, op := range doc.Operations {
		if d := fi.depth(op.SelectionSet); d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth
}

func (fi *fragmentIndex) depth(ss ast.SelectionSet) int {
	maxSubDepth := 0
	sub := func(inner ast.SelectionSet) {
		if d := fi.depth(inner); d > maxSubDepth {
			maxSubDepth = d
		}
	}
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			if len(s.SelectionSet) > 0 {
				sub(s.SelectionSet)
			}
		case *ast.InlineFragment:
			sub(s.SelectionSet)
		case *ast.FragmentSpread:
			inner, release := fi.enter(s.Name)
			if release == nil {
				continue
			}
			sub(inner)
			release()
		}
	}
	return 1 + maxSubDepth
}

func calculateComplexity(doc *ast.QueryDocument, costs map[string]int) int {
	fi := newFragmentIndex(doc)
	totalComplexity := 0
	for _, op := range doc.Operations {
		totalComplexity += fi.complexity(op.SelectionSet, costs)
	}
	return totalComplexity
}

func (fi *fragmentIndex) complexity(ss ast.SelectionSet, costs map[string]int) int {
	complexity := 0
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			cost := 1
			if c, ok := costs[s.Name]; ok {
				cost = c
			}
			if len(s.SelectionSet) > 0 {
				cost += fi.complexity(s.SelectionSet, costs)
			}
			complexity += cost
		case *ast.InlineFragment:
			complexity += fi.complexity(s.SelectionSet, costs)
		case *ast.FragmentSpread:
			inner, release := fi.enter(s.Name)
			if release == nil {
				continue
			}
			complexity += fi.complexity(inner, costs)
			release()
		}
	}
	return complexity
}

// fieldAuth checks a query's fields against the caller's verified claims.
type fieldAuth struct {
	have  map[string]bool   // claims the caller actually presented
	need  map[string]string // field name -> required claim
	frags *fragmentIndex
}

func checkFieldAuth(doc *ast.QueryDocument, r *http.Request, fieldClaims map[string]string) error {
	fa := &fieldAuth{have: callerClaimSet(r), need: fieldClaims, frags: newFragmentIndex(doc)}
	for _, op := range doc.Operations {
		if err := fa.check(op.SelectionSet); err != nil {
			return err
		}
	}
	return nil
}

// callerClaimSet builds the set of claims the request has proven it holds,
// from the claims the auth middleware verified and stored in the context.
//
// It used to read them from an X-Gateon-Claims request header. Nothing in the
// gateway sets that header, so the only thing that could was the client: a
// request asking for a claim-gated field merely had to name the claim it
// needed. Roles and scopes count alongside the claim names themselves, because
// that is how an operator writes `field -> admin`.
func callerClaimSet(r *http.Request) map[string]bool {
	claims := auth.ToMap(r.Context().Value(auth.UserContextKey))
	set := make(map[string]bool, len(claims))
	for k, v := range claims {
		if !claimPresent(v) {
			continue
		}
		set[k] = true
		switch k {
		case "roles", "groups", "scope", "scp":
			for _, s := range claimValues(v) {
				set[s] = true
			}
		}
	}
	return set
}

// claimPresent reports whether a claim carries a value worth counting: a claim
// explicitly set to false, null or "" is not one the caller holds.
func claimPresent(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return strings.TrimSpace(t) != ""
	default:
		return true
	}
}

// claimValues flattens the several shapes a roles/scopes claim arrives in.
func claimValues(v any) []string {
	switch t := v.(type) {
	case string:
		return strings.FieldsFunc(t, func(r rune) bool { return r == ' ' || r == ',' })
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (fa *fieldAuth) check(ss ast.SelectionSet) error {
	for _, sel := range ss {
		if err := fa.checkSelection(sel); err != nil {
			return err
		}
	}
	return nil
}

// checkSelection applies the claim rule to one selection and descends. Split
// out of check so the loop stays a loop: the three cases each recurse, and
// inlined together they put this function over the complexity limit.
func (fa *fieldAuth) checkSelection(sel ast.Selection) error {
	switch s := sel.(type) {
	case *ast.Field:
		if requiredClaim, ok := fa.need[s.Name]; ok && !fa.have[requiredClaim] {
			return fmt.Errorf("access denied for field: %s (requires claim: %s)", s.Name, requiredClaim)
		}
		return fa.check(s.SelectionSet)
	case *ast.InlineFragment:
		return fa.check(s.SelectionSet)
	case *ast.FragmentSpread:
		return fa.checkSpread(s.Name)
	}
	return nil
}

// checkSpread follows a fragment spread, with the cycle guard the index owns.
// A release of nil means the fragment is already open on this path, so the
// document is cyclic and descending again would not terminate.
func (fa *fieldAuth) checkSpread(name string) error {
	inner, release := fa.frags.enter(name)
	if release == nil {
		return nil
	}
	defer release()
	return fa.check(inner)
}
