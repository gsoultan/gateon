// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"context"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

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

// OffersPostQuantumKeyExchange reports whether TLS 1.3 handshakes offer the
// hybrid ML-KEM key exchanges. They are Go's default and nothing in the
// gateway sets CurvePreferences, so they are offered unless
// GODEBUG=tlsmlkem=0 turned them off. That is all the post-quantum
// cryptography the gateway does: no certificate or signature uses ML-DSA.
//
// The Diagnostics API and the live metrics snapshot both report it; the
// snapshot said true unconditionally, under a comment claiming ML-DSA too.
func OffersPostQuantumKeyExchange() bool {
	for _, setting := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if strings.TrimSpace(setting) == "tlsmlkem=0" {
			return false
		}
	}
	return true
}
