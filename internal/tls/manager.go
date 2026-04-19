package tls

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TLSManager defines the contract for TLS certificate loading and ACME challenge handling.
// It is implemented by Manager.
type TLSManager interface {
	GetTLSConfig() (*tls.Config, error)
	LoadCertificate(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error)
	LoadCA(caFile string) (*x509.CertPool, error)
	LoadCAData(caFile string) ([]byte, error)
	Certificates() []CertificateConfig
	ValidateCertificateFiles(certFile, keyFile, caFile string) (*gateonv1.CertificateValidation, error)
	ClearCache()
	UpdateConfig(cfg Config)
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
	mu     sync.RWMutex
	cache  map[string]*tls.Certificate
	pools  map[string]*x509.CertPool
	caData map[string][]byte
}

// NewManager creates a new TLS Manager.
func NewManager(cfg Config) *Manager {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "certs"
	}
	// Backward compatibility: sync top-level Email to AcmeConfig if not set
	if cfg.Acme.Email == "" {
		cfg.Acme.Email = cfg.Email
	}
	return &Manager{
		config: cfg,
		cache:  make(map[string]*tls.Certificate),
		pools:  make(map[string]*x509.CertPool),
		caData: make(map[string][]byte),
	}
}

// Certificates returns the certificates managed by this Manager.
func (m *Manager) Certificates() []CertificateConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Certificates
}

func (m *Manager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*tls.Certificate)
	m.pools = make(map[string]*x509.CertPool)
	m.caData = make(map[string][]byte)
}

func (m *Manager) UpdateConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
}

func (m *Manager) SetHostPolicy(policy func(ctx context.Context, host string) error) {
	m.config.HostPolicy = policy
}

func (m *Manager) SetCache(cache autocert.Cache) {
	m.config.Cache = cache
}

func (m *Manager) LoadCertificate(certFile, keyFile, caFile string) (*tls.Certificate, *x509.CertPool, error) {
	certFile = config.ResolvePath(certFile)
	keyFile = config.ResolvePath(keyFile)
	caFile = config.ResolvePath(caFile)

	cacheKey := certFile + "|" + keyFile + "|" + caFile
	m.mu.RLock()
	if cert, ok := m.cache[cacheKey]; ok {
		pool := m.pools[cacheKey]
		m.mu.RUnlock()
		return cert, pool, nil
	}
	m.mu.RUnlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	m.validateCertificate(&cert, nil, certFile, "")

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
		m.validateCertificate(&cert, caData, certFile, caFile)
		// Append intermediate/CA certificates to the served chain so that
		// SNI-selected certificates include the full chain automatically.
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

	m.mu.Lock()
	m.cache[cacheKey] = &cert
	m.pools[cacheKey] = clientCAs
	m.mu.Unlock()

	return &cert, clientCAs, nil
}

func (m *Manager) validateCertificate(cert *tls.Certificate, caData []byte, certFile, caFile string) *gateonv1.CertificateValidation {
	res := &gateonv1.CertificateValidation{
		Valid: true,
	}
	if len(cert.Certificate) == 0 {
		return res
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		logger.L.Warn().Err(err).Str("file", certFile).Msg("Failed to parse certificate for validation")
		res.Valid = false
		res.Warnings = append(res.Warnings, fmt.Sprintf("failed to parse certificate: %v", err))
		return res
	}

	// Check RSA Key Size
	if leaf.PublicKeyAlgorithm == x509.RSA {
		if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			bits := pub.Size() * 8
			if bits < 2048 {
				msg := fmt.Sprintf("Insecure RSA key size (%d bits) detected. RSA keys should be at least 2048 bits for TLS 1.3 compatibility.", bits)
				logger.L.Warn().
					Str("file", certFile).
					Int("bits", bits).
					Msg(msg)
				res.Warnings = append(res.Warnings, msg)
			}
		}
	}

	// Check for SHA-1
	if leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.DSAWithSHA1 || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		msg := fmt.Sprintf("Deprecated SHA-1 signature algorithm (%s) detected.", leaf.SignatureAlgorithm.String())
		logger.L.Warn().
			Str("file", certFile).
			Str("algo", leaf.SignatureAlgorithm.String()).
			Msg(msg)
		res.Warnings = append(res.Warnings, msg)
	}

	// Check for RSA/ECC Mismatch
	if len(caData) > 0 {
		var caCerts []*x509.Certificate
		rest := caData
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					caCerts = append(caCerts, c)
				}
			}
		}

		for _, ca := range caCerts {
			if leaf.PublicKeyAlgorithm != ca.PublicKeyAlgorithm {
				msg := fmt.Sprintf("Algorithm mismatch: certificate uses %s, but CA uses %s. This will cause handshake failures.", leaf.PublicKeyAlgorithm.String(), ca.PublicKeyAlgorithm.String())
				logger.L.Warn().
					Str("cert_file", certFile).
					Str("ca_file", caFile).
					Str("cert_algo", leaf.PublicKeyAlgorithm.String()).
					Str("ca_algo", ca.PublicKeyAlgorithm.String()).
					Msg(msg)
				res.Warnings = append(res.Warnings, msg)
				break
			}
		}
	}

	// Cipher Suite Recommendations
	var recommended []string
	certType := ""
	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		certType = "RSA"
		recommended = []string{
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		}
	case x509.ECDSA:
		certType = "ECDSA"
		recommended = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		}
	}

	if certType != "" {
		res.RecommendedCiphers = recommended
		logger.L.Info().
			Str("file", certFile).
			Str("cert_type", certType).
			Strs("recommended_ciphers", recommended).
			Msg("Recommendation: For TLS 1.2, use these cipher suites for optimal security and compatibility with this certificate.")
	}
	return res
}

func (m *Manager) ValidateCertificateFiles(certFile, keyFile, caFile string) (*gateonv1.CertificateValidation, error) {
	cert, err := tls.LoadX509KeyPair(config.ResolvePath(certFile), config.ResolvePath(keyFile))
	if err != nil {
		return nil, err
	}
	var caData []byte
	if caFile != "" {
		caData, _ = os.ReadFile(config.ResolvePath(caFile))
	}
	return m.validateCertificate(&cert, caData, certFile, caFile), nil
}

func (m *Manager) LoadCAData(caFile string) ([]byte, error) {
	if caFile == "" {
		return nil, nil
	}
	caFile = config.ResolvePath(caFile)

	m.mu.RLock()
	if data, ok := m.caData[caFile]; ok {
		m.mu.RUnlock()
		return data, nil
	}
	m.mu.RUnlock()

	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	m.mu.Lock()
	m.caData[caFile] = caData
	m.mu.Unlock()

	return caData, nil
}

func (m *Manager) LoadCA(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	caFile = config.ResolvePath(caFile)

	m.mu.RLock()
	if pool, ok := m.pools[caFile]; ok {
		m.mu.RUnlock()
		return pool, nil
	}
	m.mu.RUnlock()

	caData, err := m.LoadCAData(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	m.mu.Lock()
	m.pools[caFile] = pool
	m.mu.Unlock()

	return pool, nil
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
			cert, _, err := m.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile)
			if err != nil {
				return nil, err
			}
			certs = append(certs, *cert)
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
			cacheDir := config.ResolvePath(m.config.CacheDir)
			if err := os.MkdirAll(cacheDir, 0700); err != nil {
				return nil, fmt.Errorf("failed to create cert cache dir: %w", err)
			}
			cache = autocert.DirCache(cacheDir)
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
	minVer := ParseTLSVersion(m.config.MinVersion, tls.VersionTLS12)
	if minVer != 0 && minVer < tls.VersionTLS12 {
		logger.L.Warn().
			Str("version", m.config.MinVersion).
			Msg("Insecure TLS version configured. TLS 1.0 and 1.1 are deprecated and have known vulnerabilities. It is highly recommended to use at least TLS 1.2.")
	}
	tlsConfig.MinVersion = minVer
	tlsConfig.MaxVersion = ParseTLSVersion(m.config.MaxVersion, 0)
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	if m.config.ClientAuthType != "" {
		tlsConfig.ClientAuth = ParseClientAuthType(m.config.ClientAuthType)
	}

	for _, ca := range m.config.ClientAuthorities {
		caData, err := m.LoadCAData(ca.CaFile)
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

	// Safety guard: if strict mTLS is required, ensure at least one Client CA is configured.
	if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert && tlsConfig.ClientCAs == nil {
		return nil, fmt.Errorf("client_auth_type RequireAndVerifyClientCert requires at least one client_authority CA file")
	}

	if len(m.config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = ParseCipherSuites(m.config.CipherSuites)
	}

	return tlsConfig, nil
}

func ParseTLSVersion(v string, defaultVer uint16) uint16 {
	vv := strings.ToUpper(strings.TrimSpace(v))
	// Normalize variants: "TLS1.2", "TLS_1_2", "TLS12", "TLS 1.2" → TLS12
	vv = strings.ReplaceAll(vv, "_", "")
	vv = strings.ReplaceAll(vv, ".", "")
	vv = strings.ReplaceAll(vv, " ", "")
	switch vv {
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return defaultVer
	}
}

func ParseClientAuthType(v string) tls.ClientAuthType {
	switch strings.TrimSpace(v) {
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

func ParseCipherSuites(suites []string) []uint16 {
	if len(suites) == 0 {
		return nil
	}
	var ids []uint16
	for _, s := range suites {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		found := false
		// Check secure suites
		for _, suite := range tls.CipherSuites() {
			if suite.Name == s || strings.ReplaceAll(suite.Name, "TLS_", "") == s {
				ids = append(ids, suite.ID)
				found = true
				break
			}
		}
		if found {
			continue
		}
		// Check insecure suites
		for _, suite := range tls.InsecureCipherSuites() {
			if suite.Name == s || strings.ReplaceAll(suite.Name, "TLS_", "") == s {
				ids = append(ids, suite.ID)
				found = true
				break
			}
		}
	}
	if len(ids) == 0 {
		return nil
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
		cacheDir := config.ResolvePath(m.config.CacheDir)
		cache = autocert.DirCache(cacheDir)
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

	// Acme specific environment variables
	cfg.Acme.Enabled = os.Getenv("GATEON_ACME_ENABLED") == "true"
	cfg.Acme.Email = os.Getenv("GATEON_ACME_EMAIL")
	cfg.Acme.CAServer = os.Getenv("GATEON_ACME_CA_SERVER")
	cfg.Acme.ChallengeType = os.Getenv("GATEON_ACME_CHALLENGE_TYPE")

	// Backward compatibility: use top-level Email if Acme.Email is not set
	if cfg.Acme.Email == "" {
		cfg.Acme.Email = cfg.Email
	}

	// Auto-enable ACME if an email is provided and it wasn't explicitly disabled
	if !cfg.Acme.Enabled && os.Getenv("GATEON_ACME_ENABLED") == "" && cfg.Acme.Email != "" {
		cfg.Acme.Enabled = true
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
