package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/gateon/gateon/internal/logger"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"gopkg.in/yaml.v3"
)

type MiddlewareRegistry struct {
	mu          sync.RWMutex
	middlewares map[string]*gateonv1.Middleware
	path        string
}

func NewMiddlewareRegistry(path string) *MiddlewareRegistry {
	reg := &MiddlewareRegistry{
		middlewares: make(map[string]*gateonv1.Middleware),
		path:        path,
	}
	reg.load()
	return reg
}

func (r *MiddlewareRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read middlewares file")
		}
		return
	}

	var middlewares []*gateonv1.Middleware
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &middlewares); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal middlewares yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, &middlewares); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal middlewares json")
			return
		}
	}

	for _, m := range middlewares {
		r.middlewares[m.Id] = m
	}
	logger.L.Info().Int("count", len(r.middlewares)).Str("path", r.path).Msg("loaded middlewares")
}

func (r *MiddlewareRegistry) saveLocked() error {
	middlewares := slices.SortedFunc(maps.Values(r.middlewares), func(a, b *gateonv1.Middleware) int {
		return strings.Compare(a.Id, b.Id)
	})

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(middlewares)
	} else {
		data, err = json.MarshalIndent(middlewares, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal middlewares: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write middlewares file: %w", err)
	}
	return nil
}

func (r *MiddlewareRegistry) List() []*gateonv1.Middleware {
	items, _ := r.ListPaginated(0, 0, "")
	return items
}

func (r *MiddlewareRegistry) ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Middleware, int32) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*gateonv1.Middleware
	search = strings.ToLower(search)
	for _, m := range r.middlewares {
		if search == "" || strings.Contains(strings.ToLower(m.Id), search) || strings.Contains(strings.ToLower(m.Name), search) || strings.Contains(strings.ToLower(m.Type), search) {
			filtered = append(filtered, m)
		}
	}

	slices.SortFunc(filtered, func(a, b *gateonv1.Middleware) int {
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

func (r *MiddlewareRegistry) Get(id string) (*gateonv1.Middleware, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.middlewares[id]
	return m, ok
}

func (r *MiddlewareRegistry) All() map[string]*gateonv1.Middleware {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return maps.Clone(r.middlewares)
}

func (r *MiddlewareRegistry) Update(m *gateonv1.Middleware) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.middlewares[m.Id] = m
	return r.saveLocked()
}

func (r *MiddlewareRegistry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.middlewares, id)
	return r.saveLocked()
}
