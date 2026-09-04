// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteJSON(t *testing.T) {
	t.Run("writes the value and the status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteJSON(rec, http.StatusCreated, map[string]string{"id": "abc"})

		if rec.Code != http.StatusCreated {
			t.Errorf("status = %d, want 201", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
		}
		if out["id"] != "abc" {
			t.Errorf("body = %v, want id=abc", out)
		}
	})

	t.Run("an unmarshalable value becomes a 500, not a half-written body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		// A channel cannot be marshalled, so this takes the error path.
		WriteJSON(rec, http.StatusOK, make(chan int))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "chan") {
			t.Errorf("the encoding error reached the client: %s", rec.Body.String())
		}
	})
}

func TestParseRouteFilters(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  *struct{ Type, Host, Path, Status string }
	}{
		{name: "no filters at all yields nil", query: ""},
		{
			name:  "one filter is enough",
			query: "?host=example.com",
			want:  &struct{ Type, Host, Path, Status string }{Host: "example.com"},
		},
		{
			name:  "all four",
			query: "?type=http&host=a.test&path=/x&status=enabled",
			want:  &struct{ Type, Host, Path, Status string }{"http", "a.test", "/x", "enabled"},
		},
		{
			// Unrelated query parameters must not make an empty filter look set,
			// or every paginated list request would filter on nothing and match
			// nothing.
			name:  "unrelated parameters are ignored",
			query: "?page=2&pageSize=50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/routes"+tt.query, nil)
			got := ParseRouteFilters(r)

			if tt.want == nil {
				if got != nil {
					t.Fatalf("filter = %+v, want nil so the caller lists everything", got)
				}
				return
			}
			if got == nil {
				t.Fatal("filter = nil, want the parsed values")
			}
			if got.Type != tt.want.Type || got.Host != tt.want.Host ||
				got.Path != tt.want.Path || got.Status != tt.want.Status {
				t.Errorf("filter = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestSetSSEHeaders pins the two headers that are not obviously about SSE.
// nosniff keeps a browser from MIME-sniffing the stream into something else,
// and X-Accel-Buffering stops nginx holding events until its buffer fills,
// which presents as "the live view is broken" rather than as a proxy setting.
func TestSetSSEHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSSEHeaders(rec)

	for header, want := range map[string]string{
		"Content-Type":           "text/event-stream",
		"Cache-Control":          "no-cache",
		"Connection":             "keep-alive",
		"X-Content-Type-Options": "nosniff",
		"X-Accel-Buffering":      "no",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// selfSignedPEM returns a certificate whose CommonName is cn, so the filename
// derivation can be driven from a real x509 subject rather than a fixture.
func selfSignedPEM(t *testing.T, cn string, dnsNames []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestGenerateCertFilenameCannotEscapeItsDirectory is the property that matters:
// the name comes from a certificate an API caller pasted, and the result is
// joined to the certs directory and written to disk.
func TestGenerateCertFilenameCannotEscapeItsDirectory(t *testing.T) {
	hostile := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32",
		"/etc/shadow",
		"a/b/c",
		"..",
		"....//....//etc",
	}

	for _, cn := range hostile {
		t.Run(cn, func(t *testing.T) {
			name := generateCertFilename(selfSignedPEM(t, cn, nil), "cert")

			if strings.ContainsAny(name, `/\`) {
				t.Errorf("filename %q kept a path separator", name)
			}
			// The real guarantee: joined to a directory, it stays inside it.
			dir := "/var/lib/gateon/certs"
			joined := filepath.Join(dir, name)
			if !strings.HasPrefix(filepath.Clean(joined), dir+string(filepath.Separator)) {
				t.Errorf("joined path %q escaped %q", joined, dir)
			}
		})
	}
}

func TestGenerateCertFilename(t *testing.T) {
	t.Run("uses the common name and a content hash", func(t *testing.T) {
		name := generateCertFilename(selfSignedPEM(t, "api.example.com", nil), "cert")
		if !strings.HasPrefix(name, "api.example.com_") {
			t.Errorf("filename = %q, want it to start with the common name", name)
		}
		if !strings.HasSuffix(name, ".crt") {
			t.Errorf("filename = %q, want a .crt suffix", name)
		}
	})

	t.Run("falls back to a DNS name when there is no common name", func(t *testing.T) {
		name := generateCertFilename(selfSignedPEM(t, "", []string{"alt.example.com"}), "cert")
		if !strings.HasPrefix(name, "alt.example.com_") {
			t.Errorf("filename = %q, want the SAN", name)
		}
	})

	t.Run("two different certificates do not collide", func(t *testing.T) {
		a := generateCertFilename(selfSignedPEM(t, "same.example.com", nil), "cert")
		b := generateCertFilename(selfSignedPEM(t, "same.example.com", nil), "cert")
		if a == b {
			t.Errorf("two certificates with one common name produced %q twice; the second would overwrite the first", a)
		}
	})

	t.Run("suffix follows the type", func(t *testing.T) {
		for certType, wantSuffix := range map[string]string{
			"key":  ".key",
			"cert": ".crt",
			"ca":   ".crt",
			"":     ".pem",
		} {
			name := generateCertFilename("not a certificate at all", certType)
			if !strings.HasSuffix(name, wantSuffix) {
				t.Errorf("type %q gave %q, want suffix %q", certType, name, wantSuffix)
			}
		}
	})

	t.Run("unparseable content still yields a stable name", func(t *testing.T) {
		a := generateCertFilename("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----", "cert")
		b := generateCertFilename("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----", "cert")
		if a != b {
			t.Errorf("the same content produced %q and %q", a, b)
		}
		if strings.ContainsAny(a, `/\`) {
			t.Errorf("fallback filename %q contains a separator", a)
		}
	})
}
