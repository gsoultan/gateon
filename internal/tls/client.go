package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CreateTLSClientConfig creates a *tls.Config from the given gateonv1.TlsClientConfig.
func CreateTLSClientConfig(cfg *gateonv1.TlsClientConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify,
		ServerName:         cfg.ServerName,
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.CaFile != "" {
		caData, err := os.ReadFile(cfg.CaFile)
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
