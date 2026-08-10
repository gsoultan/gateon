// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"gopkg.in/yaml.v3"
)

type RouteRegistry struct {
	mu             sync.RWMutex
	routes         map[string]*gateonv1.Route
	sorted         []*gateonv1.Route            // Cached sorted list
	hostIndex      map[string][]*gateonv1.Route // host -> routes for O(1) lookup
	wildcardRoutes []*gateonv1.Route            // host wildcards or path-only routes

	hostTries       map[string]*PathTrie
	hostRegexes     map[string][]*gateonv1.Route
	wildcardTrie    *PathTrie
	wildcardRegexes []*gateonv1.Route

	path string
}

func NewRouteRegistry(path string) *RouteRegistry {
	reg := NewEmptyRouteRegistry()
	reg.path = path
	reg.load()
	return reg
}

func NewEmptyRouteRegistry() *RouteRegistry {
	return &RouteRegistry{
		routes:      make(map[string]*gateonv1.Route),
		hostIndex:   make(map[string][]*gateonv1.Route),
		hostTries:   make(map[string]*PathTrie),
		hostRegexes: make(map[string][]*gateonv1.Route),
	}
}

func (r *RouteRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.LogError("failed to read routes file", "error", err, "path", r.path)
		}
		return
	}

	var routes []*gateonv1.Route
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &routes); err != nil {
			logger.L.LogError("failed to unmarshal routes yaml", "error", err, "path", r.path)
			return
		}
	} else {
		if err := json.Unmarshal(data, &routes); err != nil {
			logger.L.LogError("failed to unmarshal routes json", "error", err, "path", r.path)
			return
		}
	}

	for _, rt := range routes {
		r.routes[rt.Id] = rt
	}
	r.rebuildSortedLocked()
	logger.L.LogInfo("loaded routes", "count", len(r.routes), "path", r.path)
}

func (r *RouteRegistry) rebuildSortedLocked() {
	// Sort by Priority DESC, then by Rule length DESC (more specific first), then by Id
	r.sorted = slices.SortedFunc(maps.Values(r.routes), func(a, b *gateonv1.Route) int {
		if a.Priority != b.Priority {
			return cmp.Compare(b.Priority, a.Priority)
		}
		if len(a.Rule) != len(b.Rule) {
			return cmp.Compare(len(b.Rule), len(a.Rule))
		}
		return strings.Compare(a.Id, b.Id)
	})

	r.wildcardRoutes = nil
	r.wildcardTrie = NewPathTrie()
	r.wildcardRegexes = nil
	clear(r.hostIndex)
	clear(r.hostTries)
	clear(r.hostRegexes)

	for _, rt := range r.sorted {
		if rt.Rule == "" {
			continue
		}
		host := hostFromRule(rt.Rule)
		path, isPrefix, isRegex := rulePathInfo(rt.Rule)

		if host != "" && RouteHostIsExact(host) {
			r.hostIndex[host] = append(r.hostIndex[host], rt)
			if isRegex {
				r.hostRegexes[host] = append(r.hostRegexes[host], rt)
			} else {
				if r.hostTries[host] == nil {
					r.hostTries[host] = NewPathTrie()
				}
				r.hostTries[host].Insert(path, isPrefix, rt)
			}
		} else {
			r.wildcardRoutes = append(r.wildcardRoutes, rt)
			if isRegex {
				r.wildcardRegexes = append(r.wildcardRegexes, rt)
			} else {
				r.wildcardTrie.Insert(path, isPrefix, rt)
			}
		}
	}

	// Flatten all tries for O(1) candidate lookup
	for _, trie := range r.hostTries {
		trie.Flatten()
	}
	r.wildcardTrie.Flatten()

	// Also sort per-host slices
	for _, items := range r.hostIndex {
		slices.SortFunc(items, func(a, b *gateonv1.Route) int {
			if a.Priority != b.Priority {
				return cmp.Compare(b.Priority, a.Priority)
			}
			if len(a.Rule) != len(b.Rule) {
				return cmp.Compare(len(b.Rule), len(a.Rule))
			}
			return strings.Compare(a.Id, b.Id)
		})
	}
}

func (r *RouteRegistry) saveLocked() error {
	routes := slices.SortedFunc(maps.Values(r.routes), func(a, b *gateonv1.Route) int {
		return strings.Compare(a.Id, b.Id)
	})

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(routes)
	} else {
		data, err = json.MarshalIndent(routes, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal routes: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0o600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}
	return nil
}

func (r *RouteRegistry) List(ctx context.Context) []*gateonv1.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sorted
}

func (r *RouteRegistry) GetByHost(host string) []*gateonv1.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hostIndex[strings.ToLower(host)]
}

func (r *RouteRegistry) ListWildcards(ctx context.Context) []*gateonv1.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.wildcardRoutes
}

func (r *RouteRegistry) GetTrieByHost(host string) (*PathTrie, []*gateonv1.Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	host = strings.ToLower(host)
	return r.hostTries[host], r.hostRegexes[host]
}

func (r *RouteRegistry) GetWildcardTrie() (*PathTrie, []*gateonv1.Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.wildcardTrie, r.wildcardRegexes
}

// RouteLister is the part of a route store RouteOrigins needs: the ability to
// enumerate routes. Taking the narrow interface rather than the whole store
// keeps the dependency honest and makes the function testable without standing
// up a registry.
type RouteLister interface {
	List(ctx context.Context) []*gateonv1.Route
}

// RouteOrigins returns the hostnames the routing table says this gateway
// answers on, taken from the Host() matchers in route rules.
//
// It exists so the WAF can tell a redirect or fetch destination on this site
// from one somewhere else without reading the request's Host header — which the
// attacker writes, and which made "Host: evil.tld" with
// "redirect_to=https://evil.tld/" compare same-origin in gwaf v0.4.0. A route's
// rule is configuration; a header is not.
//
// Routes that match on a path alone contribute nothing, which is correct: they
// say what this gateway serves, not what it is called.
func RouteOrigins(ctx context.Context, store RouteLister) []string {
	if store == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, rt := range store.List(ctx) {
		h := hostFromRule(rt.GetRule())
		// A wildcard is a matching pattern, not a name this gateway is reachable
		// at, and it must not become an origin. "Host(`*`)" is the catch-all
		// every default route uses; declaring it would hand the off-origin rules
		// a literal "*" to compare against, and an operator who saw the rule
		// enabled would have no idea it could never match. "*.example.com" is
		// excluded for the same reason — gwaf already accepts subdomains of a
		// declared origin, so the concrete parent is what belongs here.
		if h == "" || strings.Contains(h, "*") {
			continue
		}
		seen[h] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func hostFromRule(rule string) string {
	for _, q := range []string{"`", "\""} {
		prefix := "Host(" + q
		if idx := strings.Index(rule, prefix); idx >= 0 {
			rest := rule[idx+len(prefix):]
			suffix := q + ")"
			end := strings.Index(rest, suffix)
			if end > 0 {
				return strings.ToLower(rest[:end])
			}
		}
	}
	return ""
}

func rulePathInfo(rule string) (path string, isPrefix bool, isRegex bool) {
	// If the rule is complex (contains OR, negation, or multiple path conditions),
	// treat it as a regex-like rule so it's checked for all potential matches.
	if strings.Contains(rule, "||") || strings.Contains(rule, "!") {
		return "/", true, true
	}

	// Count path-related functions
	pathFns := []string{"Path(", "PathPrefix(", "PathRegex("}
	totalPathFns := 0
	for _, fn := range pathFns {
		totalPathFns += strings.Count(rule, fn)
	}
	if totalPathFns > 1 {
		return "/", true, true
	}

	for _, q := range []string{"`", "\""} {
		if idx := strings.Index(rule, "PathPrefix("+q); idx >= 0 {
			rest := rule[idx+len("PathPrefix(")+1:]
			end := strings.Index(rest, q+")")
			if end > 0 {
				return rest[:end], true, false
			}
		}
		if idx := strings.Index(rule, "PathRegex("+q); idx >= 0 {
			rest := rule[idx+len("PathRegex(")+1:]
			end := strings.Index(rest, q+")")
			if end > 0 {
				return rest[:end], false, true
			}
		}
		if idx := strings.Index(rule, "Path("+q); idx >= 0 {
			rest := rule[idx+len("Path(")+1:]
			end := strings.Index(rest, q+")")
			if end > 0 {
				return rest[:end], false, false
			}
		}
	}
	return "/", true, false // Matches everything by default
}

func pathFromRule(rule string) string {
	path, _, _ := rulePathInfo(rule)
	return strings.ToLower(path)
}

func (r *RouteRegistry) ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *RouteFilter) ([]*gateonv1.Route, int32) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*gateonv1.Route
	search = strings.ToLower(search)
	for _, rt := range r.routes {
		if search != "" && !strings.Contains(strings.ToLower(rt.Id), search) && !strings.Contains(strings.ToLower(rt.Name), search) && !strings.Contains(strings.ToLower(rt.Rule), search) && !strings.Contains(strings.ToLower(rt.ServiceId), search) {
			continue
		}
		if filter != nil {
			if filter.Type != "" && !strings.EqualFold(rt.Type, filter.Type) {
				continue
			}
			if filter.Host != "" {
				h := hostFromRule(rt.Rule)
				if !strings.Contains(h, strings.ToLower(filter.Host)) && !strings.Contains(strings.ToLower(rt.Rule), strings.ToLower(filter.Host)) {
					continue
				}
			}
			if filter.Path != "" {
				p := pathFromRule(rt.Rule)
				if !strings.Contains(p, strings.ToLower(filter.Path)) && !strings.Contains(strings.ToLower(rt.Rule), strings.ToLower(filter.Path)) {
					continue
				}
			}
			if filter.Status == "active" && rt.Disabled {
				continue
			}
			if filter.Status == "paused" && !rt.Disabled {
				continue
			}
		}
		filtered = append(filtered, rt)
	}

	slices.SortFunc(filtered, func(a, b *gateonv1.Route) int {
		return strings.Compare(a.Id, b.Id)
	})

	totalCount := int32(len(filtered))
	if pageSize <= 0 {
		return filtered, totalCount
	}

	start := page * pageSize
	if start < 0 {
		start = 0
	}
	if start >= totalCount {
		return nil, totalCount
	}

	end := start + pageSize
	if end > totalCount {
		end = totalCount
	}

	return filtered[start:end], totalCount
}

func (r *RouteRegistry) All(ctx context.Context) map[string]*gateonv1.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return maps.Clone(r.routes)
}

func (r *RouteRegistry) Get(ctx context.Context, id string) (*gateonv1.Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rt, ok := r.routes[id]
	return rt, ok
}

func (r *RouteRegistry) Update(ctx context.Context, rt *gateonv1.Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes[rt.Id] = rt
	r.rebuildSortedLocked()
	return r.saveLocked()
}

func (r *RouteRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.routes, id)
	r.rebuildSortedLocked()
	return r.saveLocked()
}

func (r *RouteRegistry) Mu() *sync.RWMutex {
	return &r.mu
}

func (r *RouteRegistry) Routes() map[string]*gateonv1.Route {
	return r.routes
}

func (r *RouteRegistry) RebuildSortedLocked() {
	r.rebuildSortedLocked()
}
