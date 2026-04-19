package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
		data, _ := json.Marshal(gc.Tls.Certificates)
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
}
