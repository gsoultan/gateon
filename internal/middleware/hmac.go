package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// HMACConfig configures the HMAC request signing verification middleware.
type HMACConfig struct {
	Secret    string   // HMAC secret (required)
	Header    string   // Header containing signature, e.g. X-Signature-256 or X-Hub-Signature-256
	Prefix    string   // Optional prefix to strip, e.g. "sha256=" (GitHub style)
	Methods   []string // HTTP methods to verify; empty = all
	BodyLimit int64    // Max body size to read (default 1MB); 0 = 1MB
}

// HMAC returns a middleware that verifies HMAC-SHA256 signatures on request bodies.
// Used for webhook verification (e.g. GitHub, GitLab). Rejects with 401 if invalid.
func HMAC(cfg HMACConfig) (Middleware, error) {
	if cfg.Secret == "" {
		return nil, fmt.Errorf("hmac requires secret")
	}
	header := cfg.Header
	if header == "" {
		header = "X-Signature-256"
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "sha256="
	}
	secret := []byte(cfg.Secret)
	methodSet := make(map[string]bool)
	for _, m := range cfg.Methods {
		m := strings.TrimSpace(strings.ToUpper(m))
		if m != "" {
			methodSet[m] = true
		}
	}
	bodyLimit := cfg.BodyLimit
	if bodyLimit <= 0 {
		bodyLimit = 1024 * 1024 // 1MB
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(methodSet) > 0 && !methodSet[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			sigHeader := r.Header.Get(header)
			if sigHeader == "" {
				telemetry.MiddlewareHMACFailuresTotal.WithLabelValues("").Inc()
				http.Error(w, "Missing signature", http.StatusUnauthorized)
				return
			}

			sigHex := strings.TrimSpace(sigHeader)
			if prefix != "" && strings.HasPrefix(sigHex, prefix) {
				sigHex = strings.TrimSpace(sigHex[len(prefix):])
			}
			expectedSig, err := hex.DecodeString(sigHex)
			if err != nil || len(expectedSig) != sha256.Size {
				http.Error(w, "Invalid signature format", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, bodyLimit))
			if err != nil {
				http.Error(w, "Failed to read body", http.StatusBadRequest)
				return
			}
			r.Body = &bodyReader{data: body}

			mac := hmac.New(sha256.New, secret)
			mac.Write(body)
			computed := mac.Sum(nil)

			if !hmac.Equal(computed, expectedSig) {
				telemetry.MiddlewareHMACFailuresTotal.WithLabelValues("").Inc()
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

type bodyReader struct {
	data []byte
	read int
}

func (b *bodyReader) Read(p []byte) (n int, err error) {
	if b.read >= len(b.data) {
		return 0, io.EOF
	}
	n = copy(p, b.data[b.read:])
	b.read += n
	return n, nil
}

func (b *bodyReader) Close() error {
	return nil
}
