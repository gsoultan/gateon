package config

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"gopkg.in/yaml.v3"
)

type RouteRegistry struct {
	mu     sync.RWMutex
	routes map[string]*gateonv1.Route
	path   string
}

func NewRouteRegistry(path string) *RouteRegistry {
	reg := &RouteRegistry{
		routes: make(map[string]*gateonv1.Route),
		path:   path,
	}
	reg.load()
	return reg
}

func (r *RouteRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read routes file")
		}
		return
	}

	var routes []*gateonv1.Route
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &routes); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal routes yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, &routes); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal routes json")
			return
		}
	}

	for _, rt := range routes {
		r.routes[rt.Id] = rt
	}
	logger.L.Info().Int("count", len(r.routes)).Str("path", r.path).Msg("loaded routes")
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

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}
	return nil
}

func (r *RouteRegistry) List(ctx context.Context) []*gateonv1.Route {
	items, _ := r.ListPaginated(ctx, 0, 0, "", nil)
	return items
}

func hostFromRule(rule string) string {
	if idx := strings.Index(rule, "Host(`"); idx >= 0 {
		rest := rule[idx+6:]
		end := strings.Index(rest, "`)")
		if end > 0 {
			return strings.ToLower(rest[:end])
		}
	}
	return ""
}

func pathFromRule(rule string) string {
	for _, prefix := range []string{"PathPrefix(`", "Path(`", "PathRegex(`"} {
		if idx := strings.Index(rule, prefix); idx >= 0 {
			rest := rule[idx+len(prefix):]
			end := strings.Index(rest, "`)")
			if end > 0 {
				return strings.ToLower(rest[:end])
			}
		}
	}
	return strings.ToLower(rule)
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
			if filter.Type != "" && strings.ToLower(rt.Type) != strings.ToLower(filter.Type) {
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
	return r.saveLocked()
}

func (r *RouteRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.routes, id)
	return r.saveLocked()
}
