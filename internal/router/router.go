// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Package router provides request routing functionality based on Rules and EntryPoints.
package router

import (
	"cmp"
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	ruleCache sync.Map // map[string]Matcher
)

func GetMatcher(rule string) Matcher {
	if m, ok := ruleCache.Load(rule); ok {
		return m.(Matcher)
	}

	m := parseRule(rule)
	if actual, loaded := ruleCache.LoadOrStore(rule, m); loaded {
		return actual.(Matcher)
	}
	return m
}

type Matcher struct {
	host              string
	hostNegated       bool
	hostRegex         *regexp.Regexp
	hostRegexNegated  bool
	path              string
	pathNegated       bool
	pathPrefix        string
	pathPrefixNegated bool
	pathRegex         *regexp.Regexp
	pathRegexNegated  bool
	methods           map[string]bool
	methodsNegated    bool
	headers           map[string]string // header name -> expected value
	orParts           []Matcher         // For logical OR at top level
	negated           bool              // For logical NOT at top level
}

func parseRule(rule string) Matcher {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return Matcher{}
	}

	// Basic negation support
	if strings.HasPrefix(rule, "!") {
		m := parseRule(strings.TrimSpace(rule[1:]))
		m.negated = !m.negated
		return m
	}

	// Basic OR support (top-level only)
	if strings.Contains(rule, "||") {
		// Check if it's really a top-level OR by ensuring we aren't inside parentheses
		// (very simple heuristic)
		parts := strings.Split(rule, "||")
		if len(parts) > 1 {
			m := Matcher{}
			for _, p := range parts {
				m.orParts = append(m.orParts, parseRule(p))
			}
			return m
		}
	}

	m := Matcher{}
	for _, q := range []string{"`", "\""} {
		if idx := strings.Index(rule, "Host("+q); idx >= 0 {
			m.host = extractValue(rule, "Host("+q, q+")")
			m.hostNegated = idx > 0 && rule[idx-1] == '!'
		}
		if idx := strings.Index(rule, "HostRegexp("+q); idx >= 0 {
			s := extractValue(rule, "HostRegexp("+q, q+")")
			if re, err := regexp.Compile(s); err == nil {
				m.hostRegex = re
				m.hostRegexNegated = idx > 0 && rule[idx-1] == '!'
			}
		}
		if idx := strings.Index(rule, "PathPrefix("+q); idx >= 0 {
			m.pathPrefix = extractValue(rule, "PathPrefix("+q, q+")")
			m.pathPrefixNegated = idx > 0 && rule[idx-1] == '!'
		}
		if idx := strings.Index(rule, "Path("+q); idx >= 0 {
			m.path = extractValue(rule, "Path("+q, q+")")
			m.pathNegated = idx > 0 && rule[idx-1] == '!'
		}
		if idx := strings.Index(rule, "PathRegex("+q); idx >= 0 {
			s := extractValue(rule, "PathRegex("+q, q+")")
			if re, err := regexp.Compile(s); err == nil {
				m.pathRegex = re
				m.pathRegexNegated = idx > 0 && rule[idx-1] == '!'
			}
		}
	}

	// Methods(`GET`, `POST`) or Methods("GET", "POST")
	methodsPrefix := ""
	if strings.Contains(rule, "Methods(`") {
		methodsPrefix = "Methods(`"
	} else if strings.Contains(rule, "Methods(\"") {
		methodsPrefix = "Methods(\""
	}

	if methodsPrefix != "" {
		i := strings.Index(rule, methodsPrefix)
		tail := rule[i+len(methodsPrefix):]
		// Find the correct end by matching parentheses or the specific suffix
		end := strings.Index(tail, ")")
		if end > 0 {
			inner := strings.TrimSuffix(tail[:end], "\"")
			inner = strings.TrimSuffix(inner, "`")
			m.methods = make(map[string]bool)
			// Split by either `, ` or ", "
			sep := "`, `"
			if methodsPrefix == "Methods(\"" {
				sep = "\", \""
			}
			for _, part := range strings.Split(inner, sep) {
				method := strings.TrimSpace(strings.ToUpper(strings.Trim(part, "`\"")))
				if method != "" {
					m.methods[method] = true
				}
			}
		}
	}
	// Headers support is complex, let's just add basic support for both quote types
	for _, q := range []string{"`", "\""} {
		prefix := "Headers(" + q
		rulePtr := rule
		for {
			idx := strings.Index(rulePtr, prefix)
			if idx < 0 {
				break
			}
			rest := rulePtr[idx+len(prefix):]
			qIdx := strings.Index(rest, q)
			if qIdx < 0 {
				break
			}
			name := rest[:qIdx]
			rest = strings.TrimLeft(rest[qIdx+1:], " ")
			if !strings.HasPrefix(rest, ",") {
				break
			}
			rest = strings.TrimLeft(rest[1:], " ")
			if !strings.HasPrefix(rest, q) {
				break
			}
			rest = rest[1:]
			endSuffix := q + ")"
			end := strings.Index(rest, endSuffix)
			if end < 0 {
				break
			}
			value := rest[:end]
			if m.headers == nil {
				m.headers = make(map[string]string)
			}
			m.headers[http.CanonicalHeaderKey(name)] = value
			rulePtr = rest[end+len(endSuffix):]
		}
	}
	return m
}

func (m Matcher) Match(r *http.Request) bool {
	if m.negated {
		return !m.matchInner(r)
	}
	if len(m.orParts) > 0 {
		for _, part := range m.orParts {
			if part.Match(r) {
				return true
			}
		}
		return false
	}
	return m.matchInner(r)
}

func (m Matcher) HasHost() bool {
	if m.negated {
		return false // Negated rule might not imply a specific host
	}
	if len(m.orParts) > 0 {
		for _, part := range m.orParts {
			if part.HasHost() {
				return true
			}
		}
		return false
	}
	return m.host != "" || m.hostRegex != nil
}

func (m Matcher) matchInner(r *http.Request) bool {
	host := ""
	if rs := request.GetRequestState(r); rs != nil && rs.StrippedHost != "" {
		host = rs.StrippedHost
	} else {
		host = httputil.StripPort(r.Host)
	}

	if m.host != "" {
		match := HostMatches(m.host, host)
		if m.hostNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	if m.hostRegex != nil {
		match := m.hostRegex.MatchString(host)
		if m.hostRegexNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	if m.pathPrefix != "" {
		match := strings.HasPrefix(r.URL.Path, m.pathPrefix)
		if m.pathPrefixNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	if m.path != "" {
		match := r.URL.Path == m.path
		if m.pathNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	if m.pathRegex != nil {
		match := m.pathRegex.MatchString(r.URL.Path)
		if m.pathRegexNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	if len(m.methods) > 0 {
		match := m.methods[r.Method]
		// For CORS preflight (OPTIONS), we allow a match if the route supports
		// the method requested in Access-Control-Request-Method.
		if !match && r.Method == http.MethodOptions {
			reqMethod := r.Header.Get("Access-Control-Request-Method")
			if reqMethod != "" && m.methods[strings.ToUpper(reqMethod)] {
				match = true
			}
		}

		if m.methodsNegated {
			match = !match
		}
		if !match {
			return false
		}
	}
	for name, want := range m.headers {
		// Use direct map access to avoid redundant CanonicalMIMEHeaderKey calls in Header.Get
		values := r.Header[name]
		if len(values) == 0 || values[0] != want {
			// For CORS preflight (OPTIONS), we skip header checks as the browser
			// does not send the actual headers in the preflight request.
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				continue
			}
			return false
		}
	}
	return true
}

func (m Matcher) RequiredHeaders() map[string]string {
	return m.headers
}

// HostFromRule returns the host part of a rule if it contains Host(`...`), otherwise "".
// Used by SNI to select certificates for multi-host TLS.
func HostFromRule(rule string) string {
	return GetMatcher(rule).host
}

// RouteHasHostRule returns true if the rule explicitly matches against a host
// (via Host() or HostRegexp()). This is used to prioritize host-specific routes
// over generic management endpoints when they overlap (e.g. /v1).
func RouteHasHostRule(rule string) bool {
	return GetMatcher(rule).HasHost()
}

// RouteHostIsExact returns true if routeHost is an exact host (e.g. api.example.com),
// false if it is a wildcard (e.g. *.example.com). Used by SNI to prefer exact matches.
func RouteHostIsExact(routeHost string) bool {
	return config.RouteHostIsExact(routeHost)
}

// HostMatches checks if the request host matches the route's host specification,
// supporting wildcards like *.example.com.
func HostMatches(rh string, qh string) bool {
	return config.HostMatches(rh, qh)
}

// SelectRoute finds the best matching route for the given request using a high-performance Radix Tree (PathTrie).
func SelectRoute(r *http.Request, store config.RouteStore) *gateonv1.Route {
	host := ""
	if rs := request.GetRequestState(r); rs != nil && rs.StrippedHost != "" {
		host = rs.StrippedHost
	} else {
		host = httputil.StripPort(r.Host)
	}

	// 1. Try host-specific routes first (O(log N) lookup in Trie + small O(M) regex scan)
	trie, regexes := store.GetTrieByHost(host)
	if trie != nil || len(regexes) > 0 {
		if rt := SelectRouteFromTrie(r, trie, regexes); rt != nil {
			return rt
		}
	}

	// 2. Fallback to wildcard routes (wildcards, Path-only rules, etc.)
	trie, regexes = store.GetWildcardTrie()
	if trie != nil || len(regexes) > 0 {
		return SelectRouteFromTrie(r, trie, regexes)
	}

	return nil
}

// SelectRouteFromTrie narrows down candidates using the PathTrie, adds regex-based routes,
// and then performs a final prioritized match check.
func SelectRouteFromTrie(r *http.Request, trie *config.PathTrie, regexes []*gateonv1.Route) *gateonv1.Route {
	var candidates []*gateonv1.Route
	if trie != nil {
		candidates = trie.Lookup(r.URL.Path)
	}

	if len(regexes) == 0 {
		return SelectRouteFromSlice(r, candidates)
	}

	if len(candidates) == 0 {
		return SelectRouteFromSlice(r, regexes)
	}

	// If we have both, we must merge and sort them because regexes might have higher priority.
	// We optimize for the common case where one of them is empty.
	all := make([]*gateonv1.Route, 0, len(candidates)+len(regexes))
	all = append(all, candidates...)
	all = append(all, regexes...)

	slices.SortFunc(all, func(a, b *gateonv1.Route) int {
		if a.Priority != b.Priority {
			return cmp.Compare(b.Priority, a.Priority)
		}
		if len(a.Rule) != len(b.Rule) {
			return cmp.Compare(len(b.Rule), len(a.Rule))
		}
		return strings.Compare(a.Id, b.Id)
	})

	return SelectRouteFromSlice(r, all)
}

// SelectRouteFromSlice finds the best matching route from a provided slice of routes.
// The input slice is expected to be sorted by Priority DESC and Rule specificity DESC,
// allowing us to short-circuit and return the first match (O(1) on average).
func SelectRouteFromSlice(r *http.Request, routes []*gateonv1.Route) *gateonv1.Route {
	epID := ""
	if rs := request.GetRequestState(r); rs != nil {
		epID = rs.EntryPointID
	} else if val, ok := r.Context().Value(middleware.EntryPointIDContextKey).(string); ok {
		epID = val
	}

	for _, rt := range routes {
		if rt.Disabled {
			continue
		}
		// 1. Filter by EntryPoints if specified
		if len(rt.Entrypoints) > 0 {
			matchEP := false
			for _, e := range rt.Entrypoints {
				if e == epID {
					matchEP = true
					break
				}
			}
			if !matchEP {
				continue
			}
		}

		// 2. Filter by Rule
		if rt.Rule == "" {
			continue
		}

		m := GetMatcher(rt.Rule)
		if m.Match(r) {
			// Since routes are pre-sorted by Priority and Rule length,
			// the first match is guaranteed to be the "best" one.
			return rt
		}
	}
	return nil
}

// extractValue is a helper to pull string literals from rule definitions.
func extractValue(s, prefix, suffix string) string {
	start := strings.Index(s, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)
	end := strings.Index(s[start:], suffix)
	if end == -1 {
		return ""
	}
	return s[start : start+end]
}

// RouteHasMiddlewareType returns true if the route has any middleware of the given type.
func RouteHasMiddlewareType(ctx context.Context, rt *gateonv1.Route, mwStore config.MiddlewareStore, mwType string) bool {
	if mwStore == nil || mwType == "" {
		return false
	}
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}
		if mwConf, ok := mwStore.Get(ctx, mid); ok && mwConf != nil && strings.EqualFold(mwConf.Type, mwType) {
			return true
		}
	}
	return false
}

// ApplyRouteMiddlewares wraps the handler with infrastructure middlewares and user-defined middlewares from the store.
func ApplyRouteMiddlewares(h http.Handler, rt *gateonv1.Route, redisClient redis.Client, mwStore config.MiddlewareStore, globalStore config.GlobalConfigStore, ebpfManager ebpf.Manager, reputation *reputation.IPReputationStore) http.Handler {
	var chain []middleware.Middleware
	mwFactory := middleware.NewFactory(redisClient, globalStore, ebpfManager, reputation, ".")
	// Record the trusted route type so the WAF applies gRPC transport relaxations
	// only to operator-declared gRPC routes, not based on a spoofable request header.
	mwFactory.SetRouteType(rt.Type)

	// Infrastructure Middlewares (Recovery, Logging & Monitoring)
	routeLabel := cmp.Or(rt.Name, rt.Id)
	chain = append(chain,
		middleware.AccessLog(routeLabel),
		middleware.MetricsWithService(routeLabel, rt.ServiceId),
		middleware.IPMitigation(),
		middleware.UserMitigation(),
		middleware.ReputationBlocker(routeLabel),
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if rs := request.GetRequestState(r); rs != nil {
					rs.TMiddlewareStart = time.Now().UnixNano()
				}
				next.ServeHTTP(w, r)
				if rs := request.GetRequestState(r); rs != nil {
					rs.TMiddlewareEnd = time.Now().UnixNano()
				}
			})
		},
		middleware.Recovery(),
		middleware.Debugger(globalStore),
	)

	// Default CORS Bypass for preflight requests if no CORS middleware is configured.
	// This restores v1.5.0 behavior where OPTIONS requests were automatically allowed.
	if !RouteHasMiddlewareType(context.Background(), rt, mwStore, "cors") &&
		!RouteHasMiddlewareType(context.Background(), rt, mwStore, "grpcweb") {
		chain = append(chain, middleware.BypassCORS())
	}

	// Advanced Security Middlewares
	if globalStore != nil {
		if gcfg := globalStore.Get(context.Background()); gcfg != nil && gcfg.SecurityAdvanced != nil {
			adv := gcfg.SecurityAdvanced
			// Tarpit should be early to slow down attackers before processing
			if adv.Tarpit != nil && adv.Tarpit.Enabled {
				chain = append(chain, middleware.Tarpit(
					time.Duration(adv.Tarpit.DelayBaseMs)*time.Millisecond,
					time.Duration(adv.Tarpit.DelayMaxMs)*time.Millisecond,
					adv.Tarpit.ScoreThreshold,
				))
			}
			// PoW challenge
			if adv.Pow != nil && adv.Pow.Enabled {
				chain = append(chain, middleware.Pow(int(adv.Pow.Difficulty), adv.Pow.ScoreThreshold, adv.Pow.Secret, routeLabel))
			}
			// Deception
			if adv.Deception != nil && adv.Deception.Enabled {
				chain = append(chain, middleware.Deception(middleware.DeceptionConfig{
					HoneypotPaths:        adv.Deception.HoneypotPaths,
					InjectInvisibleLinks: adv.Deception.InjectInvisibleLinks,
					InvisibleLinkPaths:   adv.Deception.InvisibleLinkPaths,
					HoneyForms:           adv.Deception.HoneyForms,
					CanaryHeader:         adv.Deception.CanaryHeader,
					CanaryToken:          adv.Deception.CanaryToken,
					EnableTrollResponse:  adv.Deception.EnableTrollResponse,
					RouteID:              routeLabel,
				}))
			}
			// Entropy
			if adv.Entropy != nil && adv.Entropy.Enabled {
				chain = append(chain, middleware.Entropy(adv.Entropy.Threshold, routeLabel))
			}
			// TLS Binding
			if adv.TlsBinding != nil && adv.TlsBinding.Enabled {
				cookieName := adv.TlsBinding.CookieName
				if cookieName == "" {
					cookieName = "session"
				}
				chain = append(chain, middleware.TlsBinding(cookieName))
			}
		}
	}

	// Set the route name once for the user middlewares and the inner proxy
	// handler, rather than re-allocating a context value on every middleware on
	// every request. Placed after the infrastructure/security middlewares so it
	// does not alter their metrics-skip behavior, which keys off an unset name.
	chain = append(chain, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := middleware.GetRequestState(r); rs != nil {
				rs.RouteName = routeLabel
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.RouteNameContextKey, routeLabel)))
		})
	})

	// Resolve and append user-defined middlewares from the registry
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}

		if mwStore != nil {
			if mwConf, ok := mwStore.Get(context.Background(), mid); ok {
				mw, err := mwFactory.Create(mwConf, routeLabel)
				if err == nil {
					wrapped := func(next http.Handler) http.Handler {
						h := mw(next)
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							h.ServeHTTP(w, r)
						})
					}
					chain = append(chain, wrapped)
				}
			}
		}
	}

	// Global WAF: when enabled in the global config, protect every route with the
	// full OWASP CRS (plus malware/ransomware detection) without requiring a
	// per-route "waf" middleware to be attached. Placed after the user-defined
	// middlewares so it runs closer to the proxy: on the response path it sees
	// uncompressed data (running before Gzip) and on the request path it runs
	// after Auth, avoiding inspection of blocked/unauthenticated traffic and
	// preventing interference with high-entropy auth headers.
	if gwaf, err := mwFactory.CreateGlobalWAF(); err != nil {
		logger.L.LogError("failed to build global WAF middleware", "error", err, "route", routeLabel)
	} else if gwaf != nil {
		chain = append(chain, gwaf)
	}

	// Final Service Timing Wrapper (placed last in chain, closest to proxy)
	chain = append(chain, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := request.GetRequestState(r); rs != nil {
				rs.TServiceStart = time.Now().UnixNano()
			}
			next.ServeHTTP(w, r)
			if rs := request.GetRequestState(r); rs != nil {
				rs.TServiceEnd = time.Now().UnixNano()
			}
		})
	})

	if len(chain) > 0 {
		h = middleware.Chain(chain...)(h)
	}

	return h
}
