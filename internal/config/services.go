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

type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]*gateonv1.Service
	path     string
}

func NewServiceRegistry(path string) *ServiceRegistry {
	reg := &ServiceRegistry{
		services: make(map[string]*gateonv1.Service),
		path:     path,
	}
	reg.load()
	return reg
}

func (r *ServiceRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read services file")
		}
		return
	}

	var services []*gateonv1.Service
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &services); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal services yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, &services); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal services json")
			return
		}
	}

	for _, s := range services {
		r.services[s.Id] = s
	}
	logger.L.Info().Int("count", len(r.services)).Str("path", r.path).Msg("loaded services")
}

func (r *ServiceRegistry) saveLocked() error {
	services := slices.SortedFunc(maps.Values(r.services), func(a, b *gateonv1.Service) int {
		return strings.Compare(a.Id, b.Id)
	})

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(services)
	} else {
		data, err = json.MarshalIndent(services, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal services: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write services file: %w", err)
	}
	return nil
}

func (r *ServiceRegistry) List(ctx context.Context) []*gateonv1.Service {
	items, _ := r.ListPaginated(ctx, 0, 0, "")
	return items
}

func (r *ServiceRegistry) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*gateonv1.Service
	search = strings.ToLower(search)
	for _, s := range r.services {
		if search == "" || strings.Contains(strings.ToLower(s.Id), search) || strings.Contains(strings.ToLower(s.Name), search) {
			filtered = append(filtered, s)
		}
	}

	slices.SortFunc(filtered, func(a, b *gateonv1.Service) int {
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

func (r *ServiceRegistry) Get(ctx context.Context, id string) (*gateonv1.Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.services[id]
	return s, ok
}

func (r *ServiceRegistry) Update(ctx context.Context, s *gateonv1.Service) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.services[s.Id] = s
	return r.saveLocked()
}

func (r *ServiceRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.services, id)
	return r.saveLocked()
}
