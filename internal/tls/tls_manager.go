package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"golang.org/x/crypto/acme/autocert"
)

// TLSManager defines the contract for TLS certificate loading and ACME challenge handling.
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
