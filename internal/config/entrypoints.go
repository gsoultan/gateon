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

type EntryPointRegistry struct {
	mu          sync.RWMutex
	entryPoints map[string]*gateonv1.EntryPoint
	path        string
}

func NewEntryPointRegistry(path string) *EntryPointRegistry {
	reg := &EntryPointRegistry{
		entryPoints: make(map[string]*gateonv1.EntryPoint),
		path:        path,
	}
	reg.load()
	return reg
}

func (r *EntryPointRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read entrypoints file")
		}
		return
	}

	var entryPoints []*gateonv1.EntryPoint
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &entryPoints); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal entrypoints yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, &entryPoints); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal entrypoints json")
			return
		}
	}

	for _, ep := range entryPoints {
		r.entryPoints[ep.Id] = ep
	}
	logger.L.Info().Int("count", len(r.entryPoints)).Str("path", r.path).Msg("loaded entrypoints")
}

func (r *EntryPointRegistry) saveLocked() error {
	entryPoints := slices.SortedFunc(maps.Values(r.entryPoints), func(a, b *gateonv1.EntryPoint) int {
		return strings.Compare(a.Id, b.Id)
	})

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(entryPoints)
	} else {
		data, err = json.MarshalIndent(entryPoints, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal entrypoints: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write entrypoints file: %w", err)
	}
	return nil
}

func (r *EntryPointRegistry) List(ctx context.Context) []*gateonv1.EntryPoint {
	items, _ := r.ListPaginated(ctx, 0, 0, "")
	return items
}

func (r *EntryPointRegistry) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*gateonv1.EntryPoint
	search = strings.ToLower(search)
	for _, ep := range r.entryPoints {
		if search == "" || strings.Contains(strings.ToLower(ep.Id), search) || strings.Contains(strings.ToLower(ep.Name), search) || strings.Contains(strings.ToLower(ep.Address), search) {
			filtered = append(filtered, ep)
		}
	}

	slices.SortFunc(filtered, func(a, b *gateonv1.EntryPoint) int {
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

func (r *EntryPointRegistry) Get(ctx context.Context, id string) (*gateonv1.EntryPoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ep, ok := r.entryPoints[id]
	return ep, ok
}

func (r *EntryPointRegistry) Update(ctx context.Context, ep *gateonv1.EntryPoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entryPoints[ep.Id] = ep
	return r.saveLocked()
}

func (r *EntryPointRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.entryPoints, id)
	return r.saveLocked()
}
