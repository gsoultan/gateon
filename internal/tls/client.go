package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CreateTLSClientConfig creates a *tls.Config from the given gateonv1.TlsClientConfig.
//
// SECURITY: verification is ON by default. When no client-TLS config is present
// we return a verifying config (not InsecureSkipVerify), so the gateway never
// silently accepts an unverified upstream certificate. Certificate verification
// is only skipped when the operator explicitly sets SkipVerify=true.
func CreateTLSClientConfig(cfg *gateonv1.TlsClientConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify, // only when explicitly requested
		ServerName:         cfg.ServerName,
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		certFile := config.ResolvePath(cfg.CertFile)
		keyFile := config.ResolvePath(cfg.KeyFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.CaFile != "" {
		caFile := config.ResolvePath(cfg.CaFile)
		caData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	return tlsConfig, nil
}
