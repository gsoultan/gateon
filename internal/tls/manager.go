package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TLSManager defines the contract for TLS certificate loading and ACME challenge handling.
// It is implemented by Manager.
type TLSManager interface {
	GetTLSConfig() (*tls.Config, error)
	LoadCertificate(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error)
	HTTPChallengeHandler(fallback http.Handler) http.Handler
	SetHostPolicy(policy func(ctx context.Context, host string) error)
	SetCache(cache autocert.Cache)
}

// Config holds TLS configuration.
type Config struct {
	Enabled           bool
	Email             string
	Domains           []string
	CacheDir          string
	MinVersion        string
	MaxVersion        string
	ClientAuthType    string
	CipherSuites      []string
	Certificates      []CertificateConfig
	ClientAuthorities []ClientAuthorityConfig
	Acme              AcmeConfig
	Cache             autocert.Cache
	HostPolicy        func(ctx context.Context, host string) error
}

type AcmeConfig struct {
	Enabled       bool
	Email         string
	CAServer      string
	ChallengeType string // "http", "tls-alpn"
}

type CertificateConfig struct {
	ID       string
	Name     string
	CertFile string
	KeyFile  string
	CaFile   string
}

type ClientAuthorityConfig struct {
	ID     string
	Name   string
	CaFile string
}

// Manager handles TLS certificates and ACME.
type Manager struct {
	config Config
}

// NewManager creates a new TLS Manager.
func NewManager(cfg Config) *Manager {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "certs"
	}
	return &Manager{config: cfg}
}

func (m *Manager) SetHostPolicy(policy func(ctx context.Context, host string) error) {
	m.config.HostPolicy = policy
}

func (m *Manager) SetCache(cache autocert.Cache) {
	m.config.Cache = cache
}

func (m *Manager) LoadCertificate(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	var clientCAs *x509.CertPool
	if caFile != "" {
		caData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caData) {
			return nil, nil, fmt.Errorf("failed to parse CA certificate")
		}
	}

	return &cert, clientCAs, nil
}

func (m *Manager) GetTLSConfig() (*tls.Config, error) {
	if !m.config.Enabled {
		return nil, nil
	}

	var tlsConfig *tls.Config

	if len(m.config.Certificates) > 0 {
		// Case 1: Multiple Manual Certificates
		var certs []tls.Certificate
		for _, c := range m.config.Certificates {
			cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load key pair for %s: %w", c.CertFile, err)
			}

			if c.CaFile != "" {
				caData, err := os.ReadFile(c.CaFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read CA file for %s: %w", c.CertFile, err)
				}
				// Append CA to Certificate chain
				data := caData
				for {
					var block *pem.Block
					block, data = pem.Decode(data)
					if block == nil {
						break
					}
					if block.Type == "CERTIFICATE" {
						cert.Certificate = append(cert.Certificate, block.Bytes)
					}
				}
			}
			certs = append(certs, cert)
		}
		tlsConfig = &tls.Config{
			Certificates: certs,
		}
	}

	if m.config.Acme.Enabled {
		// Case 2: ACME (Let's Encrypt)
		var cache autocert.Cache
		if m.config.Cache != nil {
			cache = m.config.Cache
		} else {
			if err := os.MkdirAll(m.config.CacheDir, 0700); err != nil {
				return nil, fmt.Errorf("failed to create cert cache dir: %w", err)
			}
			cache = autocert.DirCache(m.config.CacheDir)
		}

		hp := m.config.HostPolicy
		if hp == nil && len(m.config.Domains) > 0 {
			hp = func(_ context.Context, host string) error {
				for _, d := range m.config.Domains {
					if host == d {
						return nil
					}
				}
				return fmt.Errorf("host %q not in whitelist", host)
			}
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostPolicy(hp),
			Email:      m.config.Acme.Email,
			Cache:      cache,
		}
		if m.config.Acme.CAServer != "" {
			certManager.Client = &acme.Client{DirectoryURL: m.config.Acme.CAServer}
		}

		acmeTLSConfig := certManager.TLSConfig()
		if tlsConfig == nil {
			tlsConfig = acmeTLSConfig
		} else {
			// Combine manual certs with ACME
			tlsConfig.GetCertificate = acmeTLSConfig.GetCertificate
		}
	}

	if tlsConfig == nil {
		return nil, nil
	}

	// Apply extra configurations
	tlsConfig.MinVersion = parseTLSVersion(m.config.MinVersion, tls.VersionTLS12)
	tlsConfig.MaxVersion = parseTLSVersion(m.config.MaxVersion, 0)

	if m.config.ClientAuthType != "" {
		tlsConfig.ClientAuth = parseClientAuthType(m.config.ClientAuthType)
	}

	for _, ca := range m.config.ClientAuthorities {
		caData, err := os.ReadFile(ca.CaFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client authority file %s: %w", ca.CaFile, err)
		}
		if tlsConfig.ClientCAs == nil {
			tlsConfig.ClientCAs = x509.NewCertPool()
		}
		if !tlsConfig.ClientCAs.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse client authority certificate %s", ca.CaFile)
		}
	}

	if len(m.config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = parseCipherSuites(m.config.CipherSuites)
	}

	return tlsConfig, nil
}

func parseTLSVersion(v string, defaultVer uint16) uint16 {
	switch v {
	case "TLS1.2":
		return tls.VersionTLS12
	case "TLS1.3":
		return tls.VersionTLS13
	default:
		// TLS 1.0 and 1.1 are deprecated; treat unknown as default (TLS 1.2)
		return defaultVer
	}
}

func parseClientAuthType(v string) tls.ClientAuthType {
	switch v {
	case "NoClientCert":
		return tls.NoClientCert
	case "RequestClientCert":
		return tls.RequestClientCert
	case "RequireAnyClientCert":
		return tls.RequireAnyClientCert
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

func parseCipherSuites(suites []string) []uint16 {
	var ids []uint16
	for _, s := range suites {
		for _, suite := range tls.CipherSuites() {
			if suite.Name == s {
				ids = append(ids, suite.ID)
				break
			}
		}
	}
	return ids
}

// HTTPChallengeHandler returns a handler for ACME HTTP-01 challenges.
// This is typically needed if the server is listening on port 80.
func (m *Manager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	if !m.config.Enabled || !m.config.Acme.Enabled {
		return fallback
	}

	var cache autocert.Cache
	if m.config.Cache != nil {
		cache = m.config.Cache
	} else {
		cache = autocert.DirCache(m.config.CacheDir)
	}

	hp := m.config.HostPolicy
	if hp == nil && len(m.config.Domains) > 0 {
		hp = func(_ context.Context, host string) error {
			for _, d := range m.config.Domains {
				if host == d {
					return nil
				}
			}
			return fmt.Errorf("host %q not in whitelist", host)
		}
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostPolicy(hp),
		Email:      m.config.Acme.Email,
		Cache:      cache,
	}
	if m.config.Acme.CAServer != "" {
		certManager.Client = &acme.Client{DirectoryURL: m.config.Acme.CAServer}
	}

	return certManager.HTTPHandler(fallback)
}

// InitFromEnv initializes TLS config from environment variables.
// MinVersion defaults to TLS1.2 when unset (TLS 1.0/1.1 are insecure).
func InitFromEnv() Config {
	enabled := os.Getenv("GATEON_TLS_ENABLED") == "true"
	minVer := os.Getenv("GATEON_TLS_MIN_VERSION")
	if minVer == "" {
		minVer = "TLS1.2"
	}
	cfg := Config{
		Enabled:        enabled,
		Email:          os.Getenv("GATEON_TLS_EMAIL"),
		Domains:        splitAndTrim(os.Getenv("GATEON_TLS_DOMAINS")),
		CacheDir:       os.Getenv("GATEON_TLS_CACHE_DIR"),
		MinVersion:     minVer,
		MaxVersion:     os.Getenv("GATEON_TLS_MAX_VERSION"),
		ClientAuthType: os.Getenv("GATEON_TLS_CLIENT_AUTH_TYPE"),
		CipherSuites:   splitAndTrim(os.Getenv("GATEON_TLS_CIPHER_SUITES")),
	}

	// Support for multiple certificates from env (e.g., GATEON_TLS_CERTS="cert1.pem,key1.pem;cert2.pem,key2.pem")
	if certsEnv := os.Getenv("GATEON_TLS_CERTS"); certsEnv != "" {
		for _, pair := range strings.Split(certsEnv, ";") {
			parts := strings.Split(pair, ",")
			if len(parts) >= 2 {
				cc := CertificateConfig{
					CertFile: strings.TrimSpace(parts[0]),
					KeyFile:  strings.TrimSpace(parts[1]),
				}
				if len(parts) >= 3 {
					cc.CaFile = strings.TrimSpace(parts[2])
				}
				cfg.Certificates = append(cfg.Certificates, cc)
			}
		}
	}

	return cfg
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}
