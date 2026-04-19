package handlers

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

func registerCertHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI) {
	mux.HandleFunc("GET /v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gc := svc.GetGlobals().Get(r.Context())
		if gc == nil || gc.Tls == nil {
			_, _ = w.Write([]byte("[]"))
			return
		}

		certs := gc.Tls.Certificates
		tm := svc.GetTLSManager()
		if tm != nil {
			for _, c := range certs {
				if c.CertFile != "" && c.KeyFile != "" {
					v, err := tm.ValidateCertificateFiles(c.CertFile, c.KeyFile, c.CaFile)
					if err == nil {
						c.Validation = v
					}
				}
			}
		}

		data, _ := json.Marshal(certs)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/certs/upload", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceCerts) {
			return
		}
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("failed to parse multipart form"))
			return
		}
		file, handler, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing file"))
			return
		}
		defer file.Close()
		filename := handler.Filename
		if !strings.HasSuffix(filename, ".crt") && !strings.HasSuffix(filename, ".key") && !strings.HasSuffix(filename, ".pem") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid file type"))
			return
		}
		certsDir := filepath.Join(config.DataDir(), "certs")
		if _, err := os.Stat(certsDir); os.IsNotExist(err) {
			_ = os.MkdirAll(certsDir, 0755)
		}
		destPath := filepath.Join(certsDir, filename)
		dst, err := os.Create(destPath)
		if err != nil {
			logger.L.Error().Err(err).Str("path", destPath).Msg("failed to create certificate file")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		if _, err := io.Copy(dst, file); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Return relative path for use in config, e.g. "certs/filename"
		relPath := filepath.Join("certs", filename)
		_ = json.NewEncoder(w).Encode(map[string]string{"path": relPath})
		logger.L.Info().Str("path", destPath).Msg("certificate uploaded")
	})

	mux.HandleFunc("POST /v1/certs/paste", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceCerts) {
			return
		}

		var req struct {
			Content string `json:"content"`
			Type    string `json:"type"` // "cert", "key", "ca"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid request body"))
			return
		}

		if req.Content == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing content"))
			return
		}

		filename := generateCertFilename(req.Content, req.Type)
		certsDir := filepath.Join(config.DataDir(), "certs")
		if _, err := os.Stat(certsDir); os.IsNotExist(err) {
			_ = os.MkdirAll(certsDir, 0755)
		}

		destPath := filepath.Join(certsDir, filename)
		if err := os.WriteFile(destPath, []byte(req.Content), 0644); err != nil {
			logger.L.Error().Err(err).Str("path", destPath).Msg("failed to save pasted certificate")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		relPath := filepath.Join("certs", filename)
		_ = json.NewEncoder(w).Encode(map[string]string{"path": relPath})
		logger.L.Info().Str("path", destPath).Msg("certificate pasted and saved")
	})
}

var filenameSanitizeRegexp = regexp.MustCompile(`[^a-zA-Z0-9.-]+`)

func generateCertFilename(content string, certType string) string {
	contentBytes := []byte(strings.TrimSpace(content))
	block, _ := pem.Decode(contentBytes)

	suffix := ".pem"
	switch certType {
	case "key":
		suffix = ".key"
	case "cert", "ca":
		suffix = ".crt"
	}

	if block != nil && (block.Type == "CERTIFICATE" || strings.Contains(block.Type, "CERTIFICATE")) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			name := cert.Subject.CommonName
			if name == "" && len(cert.DNSNames) > 0 {
				name = cert.DNSNames[0]
			}
			if name != "" {
				name = filenameSanitizeRegexp.ReplaceAllString(name, "_")
				name = strings.Trim(name, "_")
				h := sha1.Sum(block.Bytes)
				return fmt.Sprintf("%s_%x%s", name, h[:4], suffix)
			}
		}
	}

	// Fallback to hash-based name
	hash := fmt.Sprintf("%x", sha1.Sum(contentBytes))
	prefix := certType
	if prefix == "" {
		prefix = "file"
	}
	return fmt.Sprintf("%s_%s%s", prefix, hash[:12], suffix)
}
