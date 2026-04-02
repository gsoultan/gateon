package telemetry

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// CertInfo holds certificate file paths and a display name for monitoring.
type CertInfo struct {
	Domain   string
	CertName string
	CertFile string
	KeyFile  string
}

// StartTLSCertMonitor starts a background goroutine that periodically checks
// TLS certificate expiry and updates the gateon_tls_certificate_expiry_seconds gauge.
// It stops when the stop channel is closed.
func StartTLSCertMonitor(certs []CertInfo, stop <-chan struct{}) {
	if len(certs) == 0 {
		return
	}

	// Run immediately on start
	updateCertExpiry(certs)

	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateCertExpiry(certs)
			case <-stop:
				return
			}
		}
	}()
}

func updateCertExpiry(certs []CertInfo) {
	for _, ci := range certs {
		cert, err := tls.LoadX509KeyPair(ci.CertFile, ci.KeyFile)
		if err != nil {
			logger.L.Warn().
				Err(err).
				Str("cert_file", ci.CertFile).
				Msg("tls_monitor: failed to load certificate")
			continue
		}

		if len(cert.Certificate) == 0 {
			continue
		}

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			logger.L.Warn().
				Err(err).
				Str("cert_file", ci.CertFile).
				Msg("tls_monitor: failed to parse certificate")
			continue
		}

		domain := ci.Domain
		if domain == "" {
			if len(leaf.DNSNames) > 0 {
				domain = leaf.DNSNames[0]
			} else {
				domain = leaf.Subject.CommonName
			}
		}

		certName := ci.CertName
		if certName == "" {
			certName = filepath.Base(ci.CertFile)
		}

		TLSCertificateExpirySeconds.WithLabelValues(domain, certName).Set(float64(leaf.NotAfter.Unix()))
	}
}
