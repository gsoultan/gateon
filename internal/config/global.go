package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gateon/gateon/internal/logger"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"gopkg.in/yaml.v3"
)

type GlobalRegistry struct {
	mu     sync.RWMutex
	config *gateonv1.GlobalConfig
	path   string
}

func NewGlobalRegistry(path string) *GlobalRegistry {
	reg := &GlobalRegistry{
		config: &gateonv1.GlobalConfig{
			Tls:       &gateonv1.TlsConfig{},
			Redis:     &gateonv1.RedisConfig{},
			Otel:      &gateonv1.OtelConfig{},
			Log:       &gateonv1.LogConfig{Level: "info", Development: true, Format: "text", PathStatsRetentionDays: 7},
			Auth:      &gateonv1.AuthConfig{},
			Transport: &gateonv1.TransportConfig{},
		},
		path: path,
	}
	reg.load()
	return reg
}

func (r *GlobalRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to read global config file")
		}
		return
	}

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, r.config); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal global config yaml")
			return
		}
	} else {
		if err := json.Unmarshal(data, r.config); err != nil {
			logger.L.Error().Err(err).Str("path", r.path).Msg("failed to unmarshal global config json")
			return
		}
	}
	logger.L.Info().Str("path", r.path).Msg("loaded global config")
}

func (r *GlobalRegistry) saveLocked() error {
	conf := r.config

	var data []byte
	var err error

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		data, err = yaml.Marshal(conf)
	} else {
		data, err = json.MarshalIndent(conf, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("marshal global config: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write global config file: %w", err)
	}
	return nil
}

func (r *GlobalRegistry) Get(ctx context.Context) *gateonv1.GlobalConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config
}

func (r *GlobalRegistry) Update(ctx context.Context, conf *gateonv1.GlobalConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = conf
	return r.saveLocked()
}
