// Package router provides request routing functionality based on Rules and EntryPoints.
package router

import (
	"cmp"
	"context"
	"net/http"
	"regexp"
	"strings"

	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	ruleCache   = make(map[string]matcher)
	ruleCacheMu sync.RWMutex
)

func getMatcher(rule string) matcher {
	ruleCacheMu.RLock()
	m, ok := ruleCache[rule]
	ruleCacheMu.RUnlock()
	if ok {
		return m
	}

	ruleCacheMu.Lock()
	defer ruleCacheMu.Unlock()
	if m, ok = ruleCache[rule]; ok {
		return m
	}

	m = parseRule(rule)
	ruleCache[rule] = m
	return m
}

type matcher struct {
	host       string
	path       string
	pathPrefix string
	pathRegex  *regexp.Regexp
	methods    map[string]bool
	headers    map[string]string // header name -> expected value
}

func parseRule(rule string) matcher {
	m := matcher{}
	if strings.Contains(rule, "Host(`") {
		m.host = extractValue(rule, "Host(`", "`)")
	}
	if strings.Contains(rule, "PathPrefix(`") {
		m.pathPrefix = extractValue(rule, "PathPrefix(`", "`)")
	}
	if strings.Contains(rule, "Path(`") {
		m.path = extractValue(rule, "Path(`", "`)")
	}
	if s := extractValue(rule, "PathRegex(`", "`)"); s != "" {
		if re, err := regexp.Compile(s); err == nil {
			m.pathRegex = re
		}
	}
	// Methods(`GET`, `POST`) - extract content between Methods(` and `), split by `, `
	if i := strings.Index(rule, "Methods(`"); i >= 0 {
		tail := rule[i+9:]
		end := strings.Index(tail, "`)")
		if end > 0 {
			inner := tail[:end]
			m.methods = make(map[string]bool)
			for _, part := range strings.Split(inner, "`, `") {
				method := strings.TrimSpace(strings.ToUpper(strings.Trim(part, "`")))
				if method != "" {
					m.methods[method] = true
				}
			}
		}
	}
	// Headers(`Name`, `value`) - name ends at `, value ends at `)
	for {
		idx := strings.Index(rule, "Headers(`")
		if idx < 0 {
			break
		}
		rest := rule[idx+9:]
		backtick := strings.Index(rest, "`")
		if backtick < 0 {
			break
		}
		name := rest[:backtick]
		rest = strings.TrimLeft(rest[backtick+1:], " ")
		if !strings.HasPrefix(rest, ",") {
			break
		}
		rest = strings.TrimLeft(rest[1:], " ")
		// value is between ` and `)
		if !strings.HasPrefix(rest, "`") {
			break
		}
		rest = rest[1:]
		end := strings.Index(rest, "`)")
		if end < 0 {
			break
		}
		value := rest[:end]
		if m.headers == nil {
			m.headers = make(map[string]string)
		}
		m.headers[http.CanonicalHeaderKey(name)] = value
		rule = rest[end+2:]
	}
	return m
}

func (m matcher) Match(r *http.Request) bool {
	if m.host != "" && !HostMatches(m.host, r.Host) {
		return false
	}
	if m.pathPrefix != "" && !strings.HasPrefix(r.URL.Path, m.pathPrefix) {
		return false
	}
	if m.path != "" && r.URL.Path != m.path {
		return false
	}
	if m.pathRegex != nil && !m.pathRegex.MatchString(r.URL.Path) {
		return false
	}
	if len(m.methods) > 0 && !m.methods[r.Method] {
		// For CORS preflight (OPTIONS), we allow a match if the route supports
		// the method requested in Access-Control-Request-Method.
		if r.Method == http.MethodOptions {
			reqMethod := r.Header.Get("Access-Control-Request-Method")
			if reqMethod != "" && m.methods[strings.ToUpper(reqMethod)] {
				goto matchMethod
			}
		}
		return false
	}
matchMethod:
	for name, want := range m.headers {
		if r.Header.Get(name) != want {
			return false
		}
	}
	return true
}

// HostFromRule returns the host part of a rule if it contains Host(`...`), otherwise "".
// Used by SNI to select certificates for multi-host TLS.
func HostFromRule(rule string) string {
	return getMatcher(rule).host
}

// RouteHostIsExact returns true if routeHost is an exact host (e.g. api.example.com),
// false if it is a wildcard (e.g. *.example.com). Used by SNI to prefer exact matches.
func RouteHostIsExact(routeHost string) bool {
	return routeHost != "" && !strings.HasPrefix(strings.ToLower(routeHost), "*.")
}

// HostMatches checks if the request host matches the route's host specification,
// supporting wildcards like *.example.com.
func HostMatches(routeHost string, reqHost string) bool {
	if routeHost == "" {
		return true
	}
	qh := strings.ToLower(reqHost)
	rh := strings.ToLower(routeHost)

	// Strip port from reqHost if present
	if idx := strings.LastIndex(qh, ":"); idx != -1 {
		qh = qh[:idx]
	}

	// Handle wildcards like *.example.com
	if strings.HasPrefix(rh, "*.") {
		suffix := rh[1:] // .example.com
		return strings.HasSuffix(qh, suffix)
	}

	return qh == rh
}

// SelectRoute finds the best matching route for the given request based on EntryPoints, Rules, and Priority.
func SelectRoute(r *http.Request, routes []*gateonv1.Route) *gateonv1.Route {
	epID, _ := r.Context().Value(middleware.EntryPointIDContextKey).(string)

	var best *gateonv1.Route
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

		m := getMatcher(rt.Rule)
		if m.Match(r) {
			// 3. Selection based on Priority and then Rule length (specificity)
			if best == nil {
				best = rt
			} else if rt.Priority > best.Priority {
				best = rt
			} else if rt.Priority == best.Priority {
				if len(rt.Rule) > len(best.Rule) {
					best = rt
				}
			}
		}
	}
	return best
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
func ApplyRouteMiddlewares(h http.Handler, rt *gateonv1.Route, redisClient redis.Client, mwStore config.MiddlewareStore, globalStore config.GlobalConfigStore) http.Handler {
	var chain []middleware.Middleware
	mwFactory := middleware.NewFactory(redisClient, globalStore)

	// Infrastructure Middlewares (Recovery, Logging & Monitoring)
	routeLabel := cmp.Or(rt.Name, rt.Id)
	chain = append(chain, middleware.Recovery(), middleware.AccessLog(routeLabel), middleware.Metrics(routeLabel))

	// Resolve and append user-defined middlewares from the registry
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}

		if mwStore != nil {
			if mwConf, ok := mwStore.Get(context.Background(), mid); ok {
				mw, err := mwFactory.Create(mwConf)
				if err == nil {
					mID := mid
					wrapped := func(next http.Handler) http.Handler {
						h := mw(next)
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							ctx := context.WithValue(r.Context(), middleware.RouteNameContextKey, routeLabel)
							logger.L.Info().
								Str("flow_step", "middleware_start").
								Str("request_id", request.GetID(r)).
								Str("middleware_id", mID).
								Msg("Executing middleware")
							h.ServeHTTP(w, r.WithContext(ctx))
						})
					}
					chain = append(chain, wrapped)
				}
			}
		}
	}

	if len(chain) > 0 {
		return middleware.Chain(chain...)(h)
	}

	return h
}
