// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

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
	acme   *autocert.Manager
	// acmeGate is the running ACME manager's only way to its CA.
	acmeGate *acmeGate
}

// acmeGate carries an ACME manager's requests to its CA until the manager is
// retired. Autocert has no way to stop the renewal timers a manager has
// scheduled, so a manager replaced for a new account or CA would go on
// renewing from the old one; closing its gate makes those attempts fail
// before they leave the process, while the new manager, which shares the
// certificate cache, renews the certificates instead.
type acmeGate struct{ retired atomic.Bool }

var errACMEManagerRetired = errors.New("ACME manager retired: the ACME account or CA server changed")

func (g *acmeGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.retired.Load() {
		return nil, errACMEManagerRetired
	}
	return http.DefaultTransport.RoundTrip(r)
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
	// HostPolicy and Cache are runtime wiring installed by the server through
	// SetHostPolicy and SetCache, not store-derived configuration. A Config
	// rebuilt from the store carries neither; letting it replace them would
	// leave ACME with autocert's default policy, which issues for every host.
	if cfg.HostPolicy == nil {
		cfg.HostPolicy = m.config.HostPolicy
	}
	if cfg.Cache == nil {
		cfg.Cache = m.config.Cache
	}
	if m.acme != nil && acmeAccountChanged(m.config, cfg) {
		// A new account or CA: the running manager is retired and the next
		// handshake that needs ACME builds one with the new settings. The
		// two share the certificate cache, so certificates already issued
		// keep being served and are renewed by the new manager.
		m.acmeGate.retired.Store(true)
		m.acme, m.acmeGate = nil, nil
		logger.L.LogInfo("the ACME email or CA server changed; certificates are now issued and renewed "+
			"with the new settings", "ca_server", cmp.Or(cfg.Acme.CAServer, autocert.DefaultACMEDirectory))
	}
	m.config = cfg
}

// acmeAccountChanged reports whether the settings the ACME account was
// registered with differ between two configs.
func acmeAccountChanged(a, b Config) bool {
	return cmp.Or(a.Acme.Email, a.Email) != cmp.Or(b.Acme.Email, b.Email) || a.Acme.CAServer != b.Acme.CAServer
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
		// #nosec G304 -- operator-configured client CA bundle for mTLS.
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
		logger.L.LogWarn("Failed to parse certificate for validation", "error", err, "file", certFile)
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
				logger.L.LogWarn(msg, "file", certFile, "bits", bits)
				res.Warnings = append(res.Warnings, msg)
			}
		}
	}
}

func (m *Manager) checkSHA1(leaf *x509.Certificate, certFile string, res *gateonv1.CertificateValidation) {
	if leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.DSAWithSHA1 || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		msg := fmt.Sprintf("Deprecated SHA-1 signature algorithm (%s) detected.", leaf.SignatureAlgorithm.String())
		logger.L.LogWarn(msg, "file", certFile, "algo", leaf.SignatureAlgorithm.String())
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
					logger.L.LogWarn(msg, "cert_file", certFile, "ca_file", caFile)
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
		logger.L.LogInfo("Cipher suite recommendations added.", "file", certFile, "cert_type", certType, "recommended_ciphers", recommended)
	}
}

func (m *Manager) ValidateCertificateFiles(certFile, keyFile, caFile string) (*gateonv1.CertificateValidation, error) {
	cert, err := tls.LoadX509KeyPair(config.ResolvePath(certFile), config.ResolvePath(keyFile))
	if err != nil {
		return nil, err
	}
	var caData []byte
	if caFile != "" {
		caData, err = os.ReadFile(config.ResolvePath(caFile))
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
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

	// #nosec G304 -- operator-configured CA bundle, cached above by path.
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

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	// Installed whether or not ACME is on now: it decides per handshake, so
	// the global switch takes effect without a restart. ACME's own
	// GetCertificate used to be fixed in here when ACME was on at startup,
	// and every per-handshake config is a clone of this one, so turning ACME
	// off left it answering until the process was restarted.
	tlsConfig.GetCertificate = m.GlobalACMECertificate
	if m.config.Acme.Enabled {
		// Built now rather than on the first handshake when ACME is on from
		// the start, so a cache directory that cannot be created stops the
		// gateway starting instead of failing handshakes.
		if _, err := m.acmeManager(); err != nil {
			return nil, err
		}
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

// GlobalACMECertificate is the base TLS config's certificate source. While
// ACME is on gateway-wide it answers from ACME; while it is off it answers
// nothing, so the configured certificates do. Where ACME cannot answer for a
// host -- one its host policy does not cover -- and certificates are
// configured, they answer instead of the handshake failing.
func (m *Manager) GlobalACMECertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	enabled, haveCerts := m.config.Acme.Enabled, len(m.config.Certificates) > 0
	m.mu.RUnlock()
	if !enabled {
		return nil, nil
	}
	cert, err := m.GetCertificate(hello)
	if err != nil && haveCerts {
		return nil, nil
	}
	return cert, err
}

// acmeManager returns the autocert manager, building it on first use.
//
// It used to exist only when ACME was on gateway-wide, while a route can take
// its certificate from ACME on its own -- the host policy authorises exactly
// those routes' hosts -- so with the global switch off every handshake for
// such a route failed with "ACME not initialized". It is also built whole
// before it is published: the manager was stored first and its host policy,
// email and client set afterwards outside the lock, which a handshake that
// triggers the build can now race.
func (m *Manager) acmeManager() (*autocert.Manager, error) {
	// The config is read under the lock: UpdateConfig replaces it while
	// handshakes are in flight.
	m.mu.RLock()
	existing, cfg := m.acme, m.config
	m.mu.RUnlock()
	if existing != nil {
		return existing, nil
	}

	cache := cfg.Cache
	if cache == nil {
		cacheDir := config.ResolvePath(cfg.CacheDir)
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cert cache dir: %w", err)
		}
		cache = autocert.DirCache(cacheDir)
	}
	gate := &acmeGate{}
	built := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: m.acmeHostPolicy(),
		Email:      cmp.Or(cfg.Acme.Email, cfg.Email),
		Client: &acme.Client{
			DirectoryURL: cmp.Or(cfg.Acme.CAServer, autocert.DefaultACMEDirectory),
			HTTPClient:   &http.Client{Transport: gate},
		},
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acme == nil {
		m.acme, m.acmeGate = built, gate
	}
	return m.acme, nil
}

// acmeHostPolicy is the configured policy, or, without one, the configured
// domains -- read when a host is checked, not when the ACME manager is built,
// so a domain added at runtime is covered.
func (m *Manager) acmeHostPolicy() autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		m.mu.RLock()
		policy, domains := m.config.HostPolicy, m.config.Domains
		m.mu.RUnlock()
		if policy != nil {
			return policy(ctx, host)
		}
		if len(domains) == 0 || slices.Contains(domains, host) {
			return nil
		}
		return fmt.Errorf("host %q not in whitelist", host)
	}
}

func (m *Manager) applyExtraTLSConfig(tlsConfig *tls.Config) error {
	minVer := ParseTLSVersion(m.config.MinVersion, tls.VersionTLS12)
	if minVer != 0 && minVer < tls.VersionTLS12 {
		logger.L.LogWarn("Insecure TLS version configured.", "version", m.config.MinVersion)
	}
	tlsConfig.MinVersion = minVer
	tlsConfig.MaxVersion = ParseTLSVersion(m.config.MaxVersion, 0)
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	if m.config.Acme.Enabled {
		// autocert answers a TLS-ALPN-01 validation on this protocol. Setting
		// the list above used to drop it from the list autocert's own config
		// carried, so the CA's validation handshake failed with "no
		// application protocol" and that challenge could never complete.
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, acme.ALPNProto)
	}

	if m.config.ClientAuthType != "" {
		tlsConfig.ClientAuth = ParseClientAuthType(m.config.ClientAuthType)
	}

	for _, ca := range m.config.ClientAuthorities {
		caData, err := m.LoadCAData(ca.CaFile)
		if err != nil {
			logger.L.LogError("failed to load client authority; it will not be trusted",
				"id", ca.ID, "name", ca.Name, "file", ca.CaFile, "error", err)
			continue
		}
		if tlsConfig.ClientCAs == nil {
			tlsConfig.ClientCAs = x509.NewCertPool()
		}
		tlsConfig.ClientCAs.AppendCertsFromPEM(caData)
	}

	if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert && tlsConfig.ClientCAs == nil {
		return fmt.Errorf("ClientAuth is set to RequireAndVerifyClientCert, but no ClientCAs are provided")
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven && tlsConfig.ClientCAs == nil {
		// A nil ClientCAs makes crypto/tls verify presented client certificates
		// against the system roots. An empty pool rejects them all, which is
		// the only honest outcome when no configured authority loaded.
		logger.L.LogError("ClientAuth is VerifyClientCertIfGiven but no client authority could be loaded; " +
			"presented client certificates will be rejected rather than verified against the system roots")
		tlsConfig.ClientCAs = x509.NewCertPool()
	}

	if len(m.config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = ParseCipherSuites(m.config.CipherSuites)
	}
	return nil
}

// HTTPChallengeHandler answers ACME HTTP-01 validations and passes everything
// else to fallback. Whether there is a manager to answer them is decided per
// request rather than once when the listener starts: the manager can be built
// later, by the first handshake for a route that takes its certificate from
// ACME while the global switch is off.
func (m *Manager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			m.mu.RLock()
			certManager := m.acme
			m.mu.RUnlock()
			if certManager != nil {
				certManager.HTTPHandler(fallback).ServeHTTP(w, r)
				return
			}
		}
		fallback.ServeHTTP(w, r)
	})
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certManager, err := m.acmeManager()
	if err != nil {
		return nil, err
	}
	return certManager.GetCertificate(hello)
}
