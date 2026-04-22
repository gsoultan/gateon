package tls

import (
	"context"

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
