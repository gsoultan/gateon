package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type GlobalRegistry struct {
	mu     sync.RWMutex
	config *gateonv1.GlobalConfig
	path   string
}

var (
	globalInstance *GlobalRegistry
	globalMu       sync.RWMutex
)

func NewGlobalRegistry(path string) *GlobalRegistry {
	reg := &GlobalRegistry{
		config: &gateonv1.GlobalConfig{
			Tls:              &gateonv1.TlsConfig{},
			Redis:            &gateonv1.RedisConfig{},
			Otel:             &gateonv1.OtelConfig{},
			Log:              &gateonv1.LogConfig{Level: "info", Development: true, Format: "text", PathStatsRetentionDays: 7},
			Auth:             &gateonv1.AuthConfig{},
			Transport:        &gateonv1.TransportConfig{},
			Waf:              &gateonv1.WafConfig{Enabled: false, UseCrs: true, ParanoiaLevel: 1},
			Ha:               &gateonv1.HaConfig{},
			AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Sensitivity: 0.5, CheckIntervalSeconds: 60},
			Ebpf:             &gateonv1.EbpfConfig{},
			Management: &gateonv1.ManagementConfig{
				Bind:       "0.0.0.0",
				Port:       "8080",
				AllowedIps: []string{"0.0.0.0/0", "::/0"},
			},
			Geoip: &gateonv1.GeoIPConfig{
				Enabled:            true,
				AutoUpdate:         true,
				UpdateIntervalDays: 30,
			},
			Debugger: &gateonv1.DebuggerConfig{
				Enabled:     false,
				MaxCaptures: 1000,
				MaxBodySize: 1024 * 64, // 64KB
			},
		},
		path: path,
	}
	reg.load()
	globalMu.Lock()
	globalInstance = reg
	globalMu.Unlock()
	return reg
}

func GetGlobalConfig() *gateonv1.GlobalConfig {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalInstance == nil {
		return nil
	}
	return globalInstance.config
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
	decryptSensitiveFields(r.config)
	logger.L.Info().Str("path", r.path).Msg("loaded global config")
}

func (r *GlobalRegistry) saveLocked() error {
	conf := proto.Clone(r.config).(*gateonv1.GlobalConfig)
	encryptSensitiveFields(conf)

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

func decryptSensitiveFields(c *gateonv1.GlobalConfig) {
	if c == nil {
		return
	}
	if c.Auth != nil {
		c.Auth.PasetoSecret = ResolveSecret(c.Auth.PasetoSecret)
		c.Auth.DatabaseUrl = ResolveSecret(c.Auth.DatabaseUrl)
		if c.Auth.DatabaseConfig != nil && c.Auth.DatabaseConfig.Password != "" {
			c.Auth.DatabaseConfig.Password = ResolveSecret(c.Auth.DatabaseConfig.Password)
		}
	}
	if c.Geoip != nil {
		c.Geoip.MaxmindLicenseKey = ResolveSecret(c.Geoip.MaxmindLicenseKey)
	}
}

func encryptSensitiveFields(c *gateonv1.GlobalConfig) {
	if c == nil {
		return
	}
	if c.Auth != nil {
		c.Auth.PasetoSecret = EncryptIfKeySet(c.Auth.PasetoSecret)
		c.Auth.DatabaseUrl = EncryptIfKeySet(c.Auth.DatabaseUrl)
		if c.Auth.DatabaseConfig != nil && c.Auth.DatabaseConfig.Password != "" {
			c.Auth.DatabaseConfig.Password = EncryptIfKeySet(c.Auth.DatabaseConfig.Password)
		}
	}
	if c.Geoip != nil {
		c.Geoip.MaxmindLicenseKey = EncryptIfKeySet(c.Geoip.MaxmindLicenseKey)
	}
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

// ConfigFileExists returns true if the global config file exists on disk.
// Used to detect first run (no global.json).
func (r *GlobalRegistry) ConfigFileExists() bool {
	_, err := os.Stat(r.path)
	return err == nil
}
