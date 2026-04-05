package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
)

func registerGeoIPHandlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/geoip/upload", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceMiddlewares) {
			return
		}
		if err := r.ParseMultipartForm(50 << 20); err != nil {
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
		defer func() {
			_ = file.Close()
		}()

		filename := filepath.Base(handler.Filename)
		if filename == "." || filename == "" || !strings.EqualFold(filepath.Ext(filename), ".mmdb") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid file type"))
			return
		}

		if err := os.MkdirAll("geoip", 0o755); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		destPath := filepath.Join("geoip", filename)
		dst, err := os.Create(destPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer func() {
			_ = dst.Close()
		}()

		if _, err := io.Copy(dst, file); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"path": destPath})
		logger.L.Info().Str("path", destPath).Msg("geoip database uploaded")
	})
}
