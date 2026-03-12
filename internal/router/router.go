// Package router provides request routing functionality based on Rules and EntryPoints.
package router

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/middleware"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/redis/go-redis/v9"
	"sync"
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
	return true
}

// HostFromRule returns the host part of a rule if it contains Host(`...`), otherwise "".
// Used by SNI to select certificates for multi-host TLS.
func HostFromRule(rule string) string {
	return getMatcher(rule).host
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

// ApplyRouteMiddlewares wraps the handler with infrastructure middlewares and user-defined middlewares from the registry.
func ApplyRouteMiddlewares(h http.Handler, rt *gateonv1.Route, redisClient *redis.Client, mwReg *config.MiddlewareRegistry) http.Handler {
	var chain []middleware.Middleware
	mwFactory := middleware.NewFactory(redisClient)

	// Infrastructure Middlewares (Logging & Monitoring)
	chain = append(chain, middleware.AccessLog(rt.Id))
	chain = append(chain, middleware.Metrics(rt.Id))

	// Resolve and append user-defined middlewares from the registry
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}

		if mwReg != nil {
			if mwConf, ok := mwReg.Get(mid); ok {
				mw, err := mwFactory.Create(mwConf)
				if err == nil {
					chain = append(chain, mw)
				}
			}
		}
	}

	if len(chain) > 0 {
		return middleware.Chain(chain...)(h)
	}

	return h
}
