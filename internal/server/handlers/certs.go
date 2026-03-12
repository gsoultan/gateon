package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/logger"
)

func registerCertHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gc := apiService.Globals.Get()
		if gc == nil || gc.Tls == nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		data, _ := json.Marshal(gc.Tls.Certificates)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/certs/upload", func(w http.ResponseWriter, r *http.Request) {
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
		destPath := "certs/" + filename
		if _, err := os.Stat("certs"); os.IsNotExist(err) {
			_ = os.Mkdir("certs", 0755)
		}
		dst, err := os.Create(destPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		if _, err := io.Copy(dst, file); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"path": destPath})
		logger.L.Info().Str("path", destPath).Msg("certificate uploaded")
	})
}
