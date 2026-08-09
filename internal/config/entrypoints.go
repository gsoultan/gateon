// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"gopkg.in/yaml.v3"
)

type EntryPointRegistry struct {
	mu          sync.RWMutex
	entryPoints atomic.Pointer[map[string]*gateonv1.EntryPoint]
	path        string
}

func NewEntryPointRegistry(path string) *EntryPointRegistry {
	reg := NewEmptyEntryPointRegistry()
	reg.path = path
	reg.load()
	return reg
}

func NewEmptyEntryPointRegistry() *EntryPointRegistry {
	reg := &EntryPointRegistry{}
	initial := make(map[string]*gateonv1.EntryPoint)
	reg.entryPoints.Store(&initial)
	return reg
}

func (r *EntryPointRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.LogError("failed to read entrypoints file", "error", err, "path", r.path)
		}
		return
	}

	var entryPoints []*gateonv1.EntryPoint
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &entryPoints); err != nil {
			logger.L.LogError("failed to unmarshal entrypoints yaml", "error", err, "path", r.path)
			return
		}
	} else {
		if err := json.Unmarshal(data, &entryPoints); err != nil {
			logger.L.LogError("failed to unmarshal entrypoints json", "error", err, "path", r.path)
			return
		}
	}

	newMap := make(map[string]*gateonv1.EntryPoint)
	for _, ep := range entryPoints {
		newMap[ep.Id] = ep
	}
	r.entryPoints.Store(&newMap)
	logger.L.LogInfo("loaded entrypoints", "count", len(newMap), "path", r.path)
}

func (r *EntryPointRegistry) saveLocked() error {
	mPtr := r.entryPoints.Load()
	if mPtr == nil {
		return nil
	}
	entryPoints := slices.SortedFunc(maps.Values(*mPtr), func(a, b *gateonv1.EntryPoint) int {
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

	if err := os.WriteFile(r.path, data, 0o600); err != nil {
		return fmt.Errorf("write entrypoints file: %w", err)
	}
	return nil
}

func (r *EntryPointRegistry) List(ctx context.Context) []*gateonv1.EntryPoint {
	items, _ := r.ListPaginated(ctx, 0, 0, "")
	return items
}

func (r *EntryPointRegistry) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32) {
	mPtr := r.entryPoints.Load()
	if mPtr == nil {
		return nil, 0
	}
	m := *mPtr
	var filtered []*gateonv1.EntryPoint
	search = strings.ToLower(search)
	for _, ep := range m {
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
	mPtr := r.entryPoints.Load()
	if mPtr == nil {
		return nil, false
	}
	ep, ok := (*mPtr)[id]
	return ep, ok
}

func (r *EntryPointRegistry) Update(ctx context.Context, ep *gateonv1.EntryPoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	mPtr := r.entryPoints.Load()
	newMap := make(map[string]*gateonv1.EntryPoint)
	if mPtr != nil {
		for k, v := range *mPtr {
			newMap[k] = v
		}
	}
	newMap[ep.Id] = ep
	r.entryPoints.Store(&newMap)
	return r.saveLocked()
}

func (r *EntryPointRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	mPtr := r.entryPoints.Load()
	if mPtr == nil {
		return nil
	}
	newMap := make(map[string]*gateonv1.EntryPoint)
	for k, v := range *mPtr {
		newMap[k] = v
	}
	delete(newMap, id)
	r.entryPoints.Store(&newMap)
	return r.saveLocked()
}

func (r *EntryPointRegistry) Mu() *sync.RWMutex {
	return &r.mu
}

func (r *EntryPointRegistry) EntryPoints() *atomic.Pointer[map[string]*gateonv1.EntryPoint] {
	return &r.entryPoints
}
