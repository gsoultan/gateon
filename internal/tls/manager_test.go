package tls

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

func TestManager_GetTLSConfig_CAChain(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a cert and a fake CA cert
	cert, _ := testutil.GenerateCert([]string{"domain.com"})
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	_ = testutil.SaveCertToPEM(cert, certPath, keyPath)

	caCert, _ := testutil.GenerateCert([]string{"My Fake CA"})
	caPath := filepath.Join(tmpDir, "ca.pem")
	// Save only the certificate part as the "CA"
	caPEM := testutil.SaveCertToPEM(caCert, caPath, filepath.Join(tmpDir, "ca-key.pem"))
	_ = caPEM

	cfg := Config{
		Enabled: true,
		Certificates: []CertificateConfig{
			{CertFile: certPath, KeyFile: keyPath, CaFile: caPath},
		},
	}
	m := NewManager(cfg)
	tlsCfg, err := m.GetTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}

	// The certificate should now have 2 parts in its chain
	if len(tlsCfg.Certificates[0].Certificate) != 2 {
		t.Errorf("expected 2 parts in certificate chain, got %d", len(tlsCfg.Certificates[0].Certificate))
	}
}

func TestManager_HTTPChallengeHandler(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		Email:    "test@example.com",
		Domains:  []string{"example.com"},
		CacheDir: t.TempDir(),
	}
	m := NewManager(cfg)

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fallback"))
	})

	handler := m.HTTPChallengeHandler(fallback)

	// Test fallback
	req := httptest.NewRequest("GET", "http://example.com/hello", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Body.String() != "fallback" {
		t.Errorf("expected fallback, got %q", w.Body.String())
	}

	// Test ACME challenge path
	req = httptest.NewRequest("GET", "http://example.com/.well-known/acme-challenge/token", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusOK && w.Body.String() == "fallback" {
		t.Errorf("expected ACME handler to intercept request")
	}
}
