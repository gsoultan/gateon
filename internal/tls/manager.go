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
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

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
		m.appendCAChainToCert(&cert, caData)
	}

	m.mu.Lock()
	m.cache[cacheKey] = &cert
	m.pools[cacheKey] = clientCAs
	m.mu.Unlock()

	return &cert, clientCAs, nil
}

func (m *Manager) appendCAChainToCert(cert *tls.Certificate, caData []byte) {
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

func (m *Manager) validateCertificate(cert *tls.Certificate, caData []byte, certFile, caFile string) *gateonv1.CertificateValidation {
	res := &gateonv1.CertificateValidation{Valid: true}
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

	m.checkRSAKeySize(leaf, certFile, res)
	m.checkSHA1(leaf, certFile, res)
	m.checkAlgorithmMismatch(leaf, caData, certFile, caFile, res)
	m.addCipherSuiteRecommendations(leaf, certFile, res)

	return res
}

func (m *Manager) checkRSAKeySize(leaf *x509.Certificate, certFile string, res *gateonv1.CertificateValidation) {
	if leaf.PublicKeyAlgorithm == x509.RSA {
		if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			bits := pub.Size() * 8
			if bits < 2048 {
				msg := fmt.Sprintf("Insecure RSA key size (%d bits) detected. RSA keys should be at least 2048 bits for TLS 1.3 compatibility.", bits)
				logger.L.Warn().Str("file", certFile).Int("bits", bits).Msg(msg)
				res.Warnings = append(res.Warnings, msg)
			}
		}
	}
}

func (m *Manager) checkSHA1(leaf *x509.Certificate, certFile string, res *gateonv1.CertificateValidation) {
	if leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.DSAWithSHA1 || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		msg := fmt.Sprintf("Deprecated SHA-1 signature algorithm (%s) detected.", leaf.SignatureAlgorithm.String())
		logger.L.Warn().Str("file", certFile).Str("algo", leaf.SignatureAlgorithm.String()).Msg(msg)
		res.Warnings = append(res.Warnings, msg)
	}
}

func (m *Manager) checkAlgorithmMismatch(leaf *x509.Certificate, caData []byte, certFile, caFile string, res *gateonv1.CertificateValidation) {
	if len(caData) > 0 {
		rest := caData
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				ca, err := x509.ParseCertificate(block.Bytes)
				if err == nil && leaf.PublicKeyAlgorithm != ca.PublicKeyAlgorithm {
					msg := fmt.Sprintf("Algorithm mismatch: certificate uses %s, but CA uses %s. This will cause handshake failures.", leaf.PublicKeyAlgorithm.String(), ca.PublicKeyAlgorithm.String())
					logger.L.Warn().Str("cert_file", certFile).Str("ca_file", caFile).Msg(msg)
					res.Warnings = append(res.Warnings, msg)
					break
				}
			}
		}
	}
}

func (m *Manager) addCipherSuiteRecommendations(leaf *x509.Certificate, certFile string, res *gateonv1.CertificateValidation) {
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
		logger.L.Info().Str("file", certFile).Str("cert_type", certType).Strs("recommended_ciphers", recommended).Msg("Cipher suite recommendations added.")
	}
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
	var err error

	if len(m.config.Certificates) > 0 {
		tlsConfig, err = m.prepareManualTLSConfig()
		if err != nil {
			return nil, err
		}
	}

	if m.config.Acme.Enabled {
		tlsConfig, err = m.applyAcmeTLSConfig(tlsConfig)
		if err != nil {
			return nil, err
		}
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	if err := m.applyExtraTLSConfig(tlsConfig); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func (m *Manager) prepareManualTLSConfig() (*tls.Config, error) {
	var certs []tls.Certificate
	for _, c := range m.config.Certificates {
		cert, _, err := m.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *cert)
	}
	return &tls.Config{Certificates: certs}, nil
}

func (m *Manager) applyAcmeTLSConfig(baseConfig *tls.Config) (*tls.Config, error) {
	cache := m.config.Cache
	if cache == nil {
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
	if baseConfig == nil {
		return acmeTLSConfig, nil
	}
	baseConfig.GetCertificate = acmeTLSConfig.GetCertificate
	return baseConfig, nil
}

func (m *Manager) applyExtraTLSConfig(tlsConfig *tls.Config) error {
	minVer := ParseTLSVersion(m.config.MinVersion, tls.VersionTLS12)
	if minVer != 0 && minVer < tls.VersionTLS12 {
		logger.L.Warn().Str("version", m.config.MinVersion).Msg("Insecure TLS version configured.")
	}
	tlsConfig.MinVersion = minVer
	tlsConfig.MaxVersion = ParseTLSVersion(m.config.MaxVersion, 0)
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	if m.config.ClientAuthType != "" {
		tlsConfig.ClientAuth = ParseClientAuthType(m.config.ClientAuthType)
	}

	for _, ca := range m.config.ClientAuthorities {
		caData, err := m.LoadCAData(ca.CaFile)
		if err == nil {
			if tlsConfig.ClientCAs == nil {
				tlsConfig.ClientCAs = x509.NewCertPool()
			}
			tlsConfig.ClientCAs.AppendCertsFromPEM(caData)
		}
	}

	if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert && tlsConfig.ClientCAs == nil {
		return fmt.Errorf("ClientAuth is set to RequireAndVerifyClientCert, but no ClientCAs are provided")
	}

	if len(m.config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = ParseCipherSuites(m.config.CipherSuites)
	}
	return nil
}

func (m *Manager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	if !m.config.Enabled || !m.config.Acme.Enabled {
		return fallback
	}

	cache := m.config.Cache
	if cache == nil {
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
