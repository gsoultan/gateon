// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// ConfigChangeFunc is invoked after a successful GlobalConfig update. It
// receives deep clones of the previous and current configuration so listeners
// can diff them safely without racing on the live config.
type ConfigChangeFunc func(oldCfg, newCfg *gateonv1.GlobalConfig)

type GlobalRegistry struct {
	mu        sync.RWMutex
	config    atomic.Pointer[gateonv1.GlobalConfig]
	certIndex atomic.Pointer[map[string]*gateonv1.Certificate] // cert ID -> certificate for O(1) lookup
	path      string
	listeners []ConfigChangeFunc

	// defaults is the shipped configuration as it stood before the file was
	// read, captured once. load() starts from a clone of this rather than from
	// the live config, so a key deleted from the file reverts to its default
	// instead of keeping the value the previous read gave it.
	//
	// Snapshotted rather than rebuilt: the defaults include a per-install
	// proof-of-work secret, and regenerating it on each load would invalidate
	// every challenge in flight.
	defaults *gateonv1.GlobalConfig

	// loadErr is why the file at path exists and did not become the
	// configuration. See LoadErr.
	loadErr error
}

var (
	globalInstance atomic.Pointer[GlobalRegistry]
)

func NewGlobalRegistry(path string) *GlobalRegistry {
	reg := &GlobalRegistry{
		path: path,
	}
	initialConfig := &gateonv1.GlobalConfig{
		Tls:       &gateonv1.TlsConfig{},
		Redis:     &gateonv1.RedisConfig{},
		Otel:      &gateonv1.OtelConfig{},
		Log:       &gateonv1.LogConfig{Level: "info", Development: true, Format: "text", PathStatsRetentionDays: 7},
		Auth:      &gateonv1.AuthConfig{},
		Transport: &gateonv1.TransportConfig{},
		Waf: &gateonv1.WafConfig{
			Enabled:       false,
			UseCrs:        true,
			ParanoiaLevel: 1,
			Clamav: &gateonv1.ClamavConfig{
				InstallationMode: gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER,
				AutoInstall:      false,
				DockerImage:      "clamav/clamav:latest",
				FullScanSchedule: "0 2 * * *", // Daily at 2 AM
				LowResourceMode:  true,
				ClamavAddr:       "tcp://localhost:3310",
			},
		},
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
			MaxBodySize: 1024 * 64, // 64KB
		},
		SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
			Deception:  &gateonv1.DeceptionConfig{},
			Tarpit:     &gateonv1.TarpitConfig{},
			Entropy:    &gateonv1.EntropyConfig{},
			Behavioral: &gateonv1.BehavioralConfig{},
			// Generated per install, never a literal. A shipped constant here
			// is a published HMAC key: the proof-of-work challenge and its
			// solution are both derived from this secret, so anyone reading
			// the repository could mint valid solutions and walk straight
			// through the bot challenge while the operator believed it was
			// holding. See DefaultPowSecret for the guard that keeps the old
			// value from being reintroduced through a config file.
			Pow:          &gateonv1.PowConfig{Secret: GenerateRandomSecret(32)},
			IpReputation: &gateonv1.IPReputationConfig{},
		},
		Alerting: &gateonv1.AlertingConfig{},
		Audit:    &gateonv1.AuditConfig{},
		Profile:  "standard",
	}
	reg.config.Store(initialConfig)
	reg.defaults = proto.Clone(initialConfig).(*gateonv1.GlobalConfig)
	idx := make(map[string]*gateonv1.Certificate)
	reg.certIndex.Store(&idx)

	reg.load()
	globalInstance.Store(reg)
	return reg
}

func GetGlobalConfig() *gateonv1.GlobalConfig {
	reg := globalInstance.Load()
	if reg == nil {
		return nil
	}
	return reg.config.Load()
}

func (r *GlobalRegistry) load() {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.loadErr = fmt.Errorf("read %s: %w", r.path, err)
			logger.L.LogError("failed to read global config file", "error", err, "path", r.path)
		}
		return
	}

	// Start from the shipped defaults, not from the config currently loaded.
	//
	// Unmarshalling into the live config merges, so any key absent from the
	// file keeps whatever the previous read put there -- and a setting deleted
	// from global.json therefore stays in force. Nothing exercises that today
	// because load() is called once, from the constructor: there is no file
	// watcher, no SIGHUP handler and no reload endpoint, and fsnotify is not
	// even a dependency. This is behaviour-identical now and correct if that
	// ever changes, which is the cheaper order to do it in.
	var cfg *gateonv1.GlobalConfig
	if r.defaults != nil {
		cfg = proto.Clone(r.defaults).(*gateonv1.GlobalConfig)
	} else {
		cfg = &gateonv1.GlobalConfig{}
	}

	if strings.HasSuffix(r.path, ".yaml") || strings.HasSuffix(r.path, ".yml") {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			r.loadErr = fmt.Errorf("parse %s: %w", r.path, err)
			logger.L.LogError("failed to unmarshal global config yaml", "error", err, "path", r.path)
			return
		}
	} else {
		if err := json.Unmarshal(data, cfg); err != nil {
			r.loadErr = fmt.Errorf("parse %s: %w", r.path, err)
			logger.L.LogError("failed to unmarshal global config json", "error", err, "path", r.path)
			return
		}
	}
	if err := decryptSensitiveFields(cfg); err != nil {
		r.loadErr = fmt.Errorf("resolve secrets in %s: %w", r.path, err)
		logger.L.LogError("global config holds a secret that cannot be read", "error", err, "path", r.path)
		return
	}
	r.config.Store(cfg)
	r.rebuildCertIndexLocked()
	logger.L.LogInfo("loaded global config", "path", r.path)
}

func (r *GlobalRegistry) rebuildCertIndexLocked() {
	cfg := r.config.Load()
	idx := make(map[string]*gateonv1.Certificate)
	if cfg != nil && cfg.Tls != nil {
		for _, c := range cfg.Tls.Certificates {
			idx[c.Id] = c
		}
	}
	r.certIndex.Store(&idx)
}

// LoadErr reports why the global config file exists and was not loaded -- it
// could not be read, or could not be parsed -- or nil when it was loaded or does
// not exist. An absent file is the first run, which reaches the setup wizard
// through it; a present one that failed is not, and the registry is then
// serving the built-in defaults: the WAF off, the management plane open to
// every address, no auth database. Startup refuses on it rather than run a
// configuration nobody chose while the file on disk says otherwise.
func (r *GlobalRegistry) LoadErr() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadErr
}

func (r *GlobalRegistry) saveLocked() error {
	// The file holds the operator's configuration, and the registry holds the
	// defaults it fell back to. Writing would replace the one with the other --
	// which the startup bootstrap did, filling in the auth block it found
	// missing -- so that correcting the typo afterwards had nothing left to
	// correct. Nothing is written over a file that was never read.
	if r.loadErr != nil {
		return fmt.Errorf("refusing to overwrite a global config that failed to load: %w", r.loadErr)
	}
	cfg := r.config.Load()
	if cfg == nil {
		return nil
	}
	conf := proto.Clone(cfg).(*gateonv1.GlobalConfig)
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
	if err := os.WriteFile(r.path, data, 0o600); err != nil {
		return fmt.Errorf("write global config file: %w", err)
	}
	return nil
}

// decryptSensitiveFields decrypts and resolves the secret fields in place. A
// field that cannot be -- ciphertext without its key, a reference nothing can
// resolve -- is an error rather than the unusable value it holds: an
// unresolved database_url used to open a SQLite file named after the
// reference, and an unresolved PASETO secret signed sessions with it.
func decryptSensitiveFields(c *gateonv1.GlobalConfig) error {
	if c == nil {
		return nil
	}
	var errs []error
	resolve := func(field string, v *string) {
		if *v == "" {
			return
		}
		out, err := ResolveSecretStrict(*v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field, err))
			return
		}
		*v = out
	}
	if c.Auth != nil {
		resolve("auth.paseto_secret", &c.Auth.PasetoSecret)
		resolve("auth.database_url", &c.Auth.DatabaseUrl)
		if c.Auth.DatabaseConfig != nil {
			resolve("auth.database_config.password", &c.Auth.DatabaseConfig.Password)
		}
	}
	if c.Geoip != nil {
		resolve("geoip.maxmind_license_key", &c.Geoip.MaxmindLicenseKey)
	}
	if c.SecurityAdvanced != nil && c.SecurityAdvanced.Pow != nil {
		resolve("security_advanced.pow.secret", &c.SecurityAdvanced.Pow.Secret)
		// Older installs persisted the shipped literal into global.json before
		// the default became per-install. Re-key them on load rather than
		// leaving a published HMAC key in service; an operator who never
		// touched the field should not stay exploitable because of when they
		// installed.
		if IsPlaceholderPowSecret(c.SecurityAdvanced.Pow.Secret) {
			c.SecurityAdvanced.Pow.Secret = GenerateRandomSecret(32)
			logger.L.LogWarn("proof-of-work secret was the shipped placeholder; generated a new one",
				"action", "rotated", "reason", "placeholder_secret")
		}
	}
	return errors.Join(errs...)
}

// DefaultPowSecret is the literal that shipped as the proof-of-work secret
// before it was generated per install. It is kept only so it can be recognised
// and rejected.
const DefaultPowSecret = "changeme"

// IsPlaceholderPowSecret reports whether s is unusable as a proof-of-work HMAC
// key: empty, or a known-published placeholder. A challenge keyed on either is
// forgeable by anyone, which makes the bot challenge worse than absent — it
// reports "protected" while admitting every attacker who bothered to look.
func IsPlaceholderPowSecret(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.EqualFold(t, DefaultPowSecret)
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
	if c.SecurityAdvanced != nil && c.SecurityAdvanced.Pow != nil {
		c.SecurityAdvanced.Pow.Secret = EncryptIfKeySet(c.SecurityAdvanced.Pow.Secret)
	}
}

func (r *GlobalRegistry) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return r.config.Load()
}

func (r *GlobalRegistry) GetCertificate(id string) (*gateonv1.Certificate, bool) {
	idxPtr := r.certIndex.Load()
	if idxPtr == nil {
		return nil, false
	}
	c, ok := (*idxPtr)[id]
	return c, ok
}

// Subscribe registers a listener that is notified after every successful
// configuration update. Listeners are invoked synchronously (in registration
// order) with clones of the old and new config, so they must not block for long
// or call back into Update. Safe for concurrent use.
func (r *GlobalRegistry) Subscribe(fn ConfigChangeFunc) {
	if fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, fn)
}

func (r *GlobalRegistry) Update(ctx context.Context, conf *gateonv1.GlobalConfig) error {
	r.mu.Lock()
	oldCfg := r.config.Load()
	r.config.Store(conf)
	r.rebuildCertIndexLocked()
	if err := r.saveLocked(); err != nil {
		r.config.Store(oldCfg)
		r.rebuildCertIndexLocked()
		r.mu.Unlock()
		return err
	}
	listeners := make([]ConfigChangeFunc, len(r.listeners))
	copy(listeners, r.listeners)
	r.mu.Unlock()

	r.notify(listeners, oldCfg, conf)
	return nil
}

// notify invokes listeners outside the registry lock with defensive clones so a
// misbehaving listener can neither deadlock the registry nor mutate live state.
func (r *GlobalRegistry) notify(listeners []ConfigChangeFunc, oldCfg, newCfg *gateonv1.GlobalConfig) {
	if len(listeners) == 0 {
		return
	}
	oldClone := cloneConfig(oldCfg)
	for _, fn := range listeners {
		fn(oldClone, cloneConfig(newCfg))
	}
}

func cloneConfig(c *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	if c == nil {
		return nil
	}
	return proto.Clone(c).(*gateonv1.GlobalConfig)
}

// ConfigFileExists returns true if the global config file exists on disk.
// Used to detect first run (no global.json).
func (r *GlobalRegistry) ConfigFileExists() bool {
	_, err := os.Stat(r.path)
	return err == nil
}

// EffectiveTrustCloudflare returns true if Cloudflare headers should be trusted,
// checking the global configuration first and falling back to the environment variable.
// trustCloudflareFromEnv resolves the environment fallback once.
//
// It used to run on every call: TrimSpace + ToLower on a getenv, which allocates.
// EffectiveTrustCloudflare is on the request path — the metrics middleware and
// the reputation identity both ask for it per request — and the fallback is
// taken on any deployment that has not written a WAF config, which includes
// every fresh install. An environment variable cannot change under a running
// process, so reading it more than once was only ever a cost.
var trustCloudflareFromEnv = sync.OnceValue(func() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("GATEON_TRUST_CLOUDFLARE_HEADERS")))
	return v == "true" || v == "1" || v == "yes"
})

func EffectiveTrustCloudflare() bool {
	gc := GetGlobalConfig()
	if gc != nil && gc.Waf != nil {
		return gc.Waf.TrustCloudflareHeaders
	}
	return trustCloudflareFromEnv()
}
