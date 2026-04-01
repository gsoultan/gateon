package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTempCACert writes a minimal self-signed CA certificate to a temp file and returns its path.
func createTempCACert(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Gateon Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	f, err := os.Create(caPath)
	if err != nil {
		t.Fatalf("create temp ca: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	return caPath
}

func TestManager_RequireAndVerifyWithoutCAs_ReturnsError(t *testing.T) {
	m := NewManager(Config{
		Enabled:        true,
		Acme:           AcmeConfig{Enabled: true, Email: "test@example.com"},
		ClientAuthType: "RequireAndVerifyClientCert",
	})

	cfg, err := m.GetTLSConfig()
	if err == nil || cfg != nil {
		t.Fatalf("expected error due to missing client CAs, got cfg=%v err=%v", cfg, err)
	}
}

func TestManager_ClientAuthoritiesBuildPool_OK(t *testing.T) {
	caPath := createTempCACert(t)

	m := NewManager(Config{
		Enabled:        true,
		Acme:           AcmeConfig{Enabled: true, Email: "test@example.com"},
		ClientAuthType: "RequireAndVerifyClientCert",
		ClientAuthorities: []ClientAuthorityConfig{{
			ID: "1", Name: "Test CA", CaFile: caPath,
		}},
	})

	cfg, err := m.GetTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected non-nil tls.Config")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatalf("expected ClientCAs to be initialized")
	}
}
