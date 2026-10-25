// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
		// #nosec G402 -- not a default. This is false unless the operator set
		// SkipVerify, the nil/disabled path above returns a verifying config,
		// and the doc comment states the contract. gosec flags the variable
		// rather than a decision, and silencing it here is honest only because
		// the decision is the operator's and is made elsewhere.
		InsecureSkipVerify: cfg.SkipVerify,
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
		// #nosec G304 -- an operator-configured CA bundle path, resolved through
		// config.ResolvePath. Naming a trust anchor is the point of the setting.
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

// ValidateClientConfig reports why the proxy could not build cfg as written.
// The proxy builds it only when a route is first served, and a file it cannot
// load there is logged and dropped: the static certificate falls back to a
// verifying config with no certificate and no custom CA, an identity is left
// out. A backend that requires mutual TLS then refuses every request while the
// dashboard shows the service saved. Saving is where an operator can still be
// told. A disabled config is not built and is not checked.
func ValidateClientConfig(cfg *gateonv1.TlsClientConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("backend TLS needs both a client certificate and its key, or neither")
	}
	if _, err := CreateTLSClientConfig(cfg); err != nil {
		return fmt.Errorf("backend TLS: %w", err)
	}
	return validateClientIdentities(cfg)
}

// validateClientIdentities refuses identities the selector would never choose
// or could not load. STATIC presents cert_file and consults no identity, so
// identities saved under it were stored and never read.
func validateClientIdentities(cfg *gateonv1.TlsClientConfig) error {
	if len(cfg.CertIdentities) == 0 {
		return nil
	}
	strategy := cfg.CertSelectionStrategy
	if strategy == gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC {
		return errors.New("client identities are chosen by host or by header; with the static strategy " +
			"only the client certificate is presented, so choose a strategy or remove the identities")
	}
	for i, item := range cfg.CertIdentities {
		name := item.Id
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		if err := validateClientIdentity(item, strategy); err != nil {
			return fmt.Errorf("client identity %s: %w", name, err)
		}
	}
	return nil
}

func validateClientIdentity(item *gateonv1.TlsClientIdentity, strategy gateonv1.TlsClientCertSelectionStrategy) error {
	if item.CertFile == "" || item.KeyFile == "" {
		return errors.New("needs both a certificate and a key")
	}
	switch strategy {
	case gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST:
		if len(item.MatchHosts) == 0 {
			return errors.New("matches no host, so it is never presented")
		}
	case gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER:
		if item.MatchHeader == "" {
			return errors.New("matches no header, so it is never presented")
		}
	}
	if _, err := tls.LoadX509KeyPair(config.ResolvePath(item.CertFile), config.ResolvePath(item.KeyFile)); err != nil {
		return fmt.Errorf("failed to load certificate and key: %w", err)
	}
	return nil
}
