package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// createTempCertKey generates a self-signed cert and key for the given host and writes them to temp files.
func createTempCertKey(t *testing.T, host string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	{
		f, _ := os.Create(certPath)
		_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = f.Close()
	}
	{
		b, _ := x509.MarshalECPrivateKey(priv)
		f, _ := os.Create(keyPath)
		_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		_ = f.Close()
	}
	return certPath, keyPath
}

// createTempCA writes a minimal self-signed CA cert to temp file.
func createTempCA(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Gateon Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	f, _ := os.Create(caPath)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = f.Close()
	return caPath
}

// minimal base tls.Config for test
func baseTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
}

func TestSetupSNI_BindsClientAuthoritiesFromTLSOption(t *testing.T) {
	host := "example.com"
	certPath, keyPath := createTempCertKey(t, host)
	caPath := createTempCA(t)

	// Prepare stores
	dir := t.TempDir()
	routesReg := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	tlsOptReg := config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))
	globalsReg := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))

	// Global TLS: certificate and client authority
	gc := &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{}}
	gc.Tls.Certificates = []*gateonv1.Certificate{{
		Id: "cert1", Name: "Test", CertFile: certPath, KeyFile: keyPath,
	}}
	gc.Tls.ClientAuthorities = []*gateonv1.ClientAuthority{{
		Id: "ca1", Name: "CA", CaFile: caPath,
	}}
	if err := globalsReg.Update(context.Background(), gc); err != nil {
		t.Fatalf("update globals: %v", err)
	}

	// TLS Option references CA
	_ = tlsOptReg.Update(context.Background(), &gateonv1.TLSOption{
		Id:                 "opt1",
		Name:               "Strict ClientAuth",
		ClientAuthType:     "RequireAndVerifyClientCert",
		ClientAuthorityIds: []string{"ca1"},
	})

	// Route with Host rule and TLS settings
	_ = routesReg.Update(context.Background(), &gateonv1.Route{
		Id:          "r1",
		Name:        "r",
		Type:        "grpc",
		Entrypoints: []string{"https"},
		Rule:        "Host(`" + host + "`)",
		Priority:    0,
		ServiceId:   "svc1",
		Tls: &gateonv1.RouteTLSConfig{
			CertificateIds: []string{"cert1"},
			OptionId:       "opt1",
		},
	})

	// TLS Manager used only to load certificates from files
	m := gtls.NewManager(gtls.Config{})

	cfg := baseTLSConfig()
	SetupSNI(cfg, m, SNIDeps{RouteStore: routesReg, GlobalStore: globalsReg, TLSOptStore: tlsOptReg})

	// Simulate handshake
	hello := &tls.ClientHelloInfo{ServerName: net.JoinHostPort(host, "443")}
	selected, err := cfg.GetConfigForClient(hello)
	if err != nil {
		t.Fatalf("GetConfigForClient error: %v", err)
	}
	if selected == nil {
		t.Fatalf("expected non-nil tls.Config for SNI host")
	}
	if selected.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth=RequireAndVerifyClientCert, got %v", selected.ClientAuth)
	}
	if selected.ClientCAs == nil {
		t.Fatalf("expected ClientCAs to be set from TLS Option client_authority_ids")
	}
}
