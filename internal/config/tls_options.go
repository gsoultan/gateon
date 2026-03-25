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

type TLSOptionRegistry struct {
	mu      sync.RWMutex
	options map[string]*gateonv1.TLSOption
	path    string
}

func NewTLSOptionRegistry(path string) *TLSOptionRegistry {
	reg := &TLSOptionRegistry{
		options: make(map[string]*gateonv1.TLSOption),
		path:    path,
	}
	reg.load()
	return reg
}

func (r *TLSOptionRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read tls options file")
		}
		return
	}

	var options []*gateonv1.TLSOption
	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, &options); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal tls options yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, &options); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal tls options json")
			return
		}
	}

	for _, opt := range options {
		r.options[opt.Id] = opt
	}
	logger.L.Info().Int("count", len(r.options)).Str("path", r.path).Msg("loaded tls options")
}

func (r *TLSOptionRegistry) saveLocked() error {
	options := slices.SortedFunc(maps.Values(r.options), func(a, b *gateonv1.TLSOption) int {
		return strings.Compare(a.Id, b.Id)
	})

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(options)
	} else {
		data, err = json.MarshalIndent(options, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal tls options: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write tls options file: %w", err)
	}
	return nil
}

func (r *TLSOptionRegistry) List(ctx context.Context) []*gateonv1.TLSOption {
	items, _ := r.ListPaginated(ctx, 0, 0, "")
	return items
}

func (r *TLSOptionRegistry) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*gateonv1.TLSOption
	search = strings.ToLower(search)
	for _, opt := range r.options {
		if search == "" || strings.Contains(strings.ToLower(opt.Id), search) || strings.Contains(strings.ToLower(opt.Name), search) || strings.Contains(strings.ToLower(opt.MinTlsVersion), search) {
			filtered = append(filtered, opt)
		}
	}

	slices.SortFunc(filtered, func(a, b *gateonv1.TLSOption) int {
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

func (r *TLSOptionRegistry) Get(ctx context.Context, id string) (*gateonv1.TLSOption, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	opt, ok := r.options[id]
	return opt, ok
}

func (r *TLSOptionRegistry) All(ctx context.Context) map[string]*gateonv1.TLSOption {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return maps.Clone(r.options)
}

func (r *TLSOptionRegistry) Update(ctx context.Context, opt *gateonv1.TLSOption) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.options[opt.Id] = opt
	return r.saveLocked()
}

func (r *TLSOptionRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.options, id)
	return r.saveLocked()
}
