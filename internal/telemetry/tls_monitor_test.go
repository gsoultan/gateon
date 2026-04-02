package telemetry

import (
	"path/filepath"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/testutil"
)

func TestStartTLSCertMonitor(t *testing.T) {
	// Generate a self-signed test certificate
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	cert, err := testutil.GenerateCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}
	if err := testutil.SaveCertToPEM(cert, certFile, keyFile); err != nil {
		t.Fatalf("failed to save cert: %v", err)
	}

	certs := []CertInfo{
		{Domain: "test.example.com", CertName: "test-cert", CertFile: certFile, KeyFile: keyFile},
	}

	stop := make(chan struct{})
	StartTLSCertMonitor(certs, stop)
	defer close(stop)

	// Verify gauge was set
	m := &dto.Metric{}
	g := TLSCertificateExpirySeconds.WithLabelValues("test.example.com", "test-cert")
	if err := g.Write(m); err != nil {
		t.Fatalf("failed to read gauge: %v", err)
	}
	val := m.GetGauge().GetValue()
	if val <= 0 {
		t.Errorf("expected positive expiry timestamp, got %f", val)
	}
}

func TestStartTLSCertMonitorNoCerts(t *testing.T) {
	stop := make(chan struct{})
	// Should not panic with empty slice
	StartTLSCertMonitor(nil, stop)
	close(stop)
}

func TestStartTLSCertMonitorInvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad-cert.pem")
	keyFile := filepath.Join(tmpDir, "bad-key.pem")

	certs := []CertInfo{
		{Domain: "bad.example.com", CertName: "bad-cert", CertFile: certFile, KeyFile: keyFile},
	}

	stop := make(chan struct{})
	// Should not panic with invalid cert files
	StartTLSCertMonitor(certs, stop)
	close(stop)
}
