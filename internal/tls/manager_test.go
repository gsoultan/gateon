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

func TestManager_LoadCertificate_AppendsCaFileToChain(t *testing.T) {
	dir := t.TempDir()

	// Generate a self-signed CA key pair.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}

	// Write CA cert PEM (the "intermediate" file).
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}

	// Generate a leaf key pair signed by the CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644); err != nil {
		t.Fatalf("write cert pem: %v", err)
	}

	keyPath := filepath.Join(dir, "key.pem")
	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0644); err != nil {
		t.Fatalf("write key pem: %v", err)
	}

	m := NewManager(Config{})

	// Without caFile: chain should have only the leaf.
	certNoCa, _, err := m.LoadCertificate(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("LoadCertificate without caFile: %v", err)
	}
	if len(certNoCa.Certificate) != 1 {
		t.Fatalf("expected 1 cert in chain without caFile, got %d", len(certNoCa.Certificate))
	}

	// With caFile: chain should have leaf + CA (2 entries).
	certWithCa, pool, err := m.LoadCertificate(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("LoadCertificate with caFile: %v", err)
	}
	if len(certWithCa.Certificate) != 2 {
		t.Fatalf("expected 2 certs in chain with caFile, got %d", len(certWithCa.Certificate))
	}
	if pool == nil {
		t.Fatalf("expected non-nil CertPool when caFile is provided")
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
