// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Upload bounds for the GeoIP database endpoint. The hard ceiling must clear a
// real GeoLite2-City.mmdb (~70 MiB) or legitimate uploads start failing.
const (
	geoIPUploadMemoryBytes = 50 << 20  // 50 MiB
	maxGeoIPUploadBytes    = 128 << 20 // 128 MiB
)

// reloadGeoIPByFilename reloads the GeoIP reader that matches the uploaded
// edition. ASN and Country databases are detected by their MaxMind filename and
// loaded into their dedicated readers; everything else reloads the City reader.
func reloadGeoIPByFilename(filename, destPath string) error {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "asn"):
		return telemetry.InitGeoIPASN(destPath)
	case strings.Contains(lower, "country"):
		return telemetry.InitGeoIPCountry(destPath)
	default:
		return telemetry.InitGeoIP(destPath)
	}
}

func registerGeoIPHandlers(mux *http.ServeMux, globalReg config.GlobalConfigStore) {
	mux.HandleFunc("POST /v1/geoip/upload", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceMiddlewares) {
			return
		}
		// ParseMultipartForm bounds memory only; the overflow goes to a temp file
		// with no limit, so without MaxBytesReader an authenticated writer can
		// fill the disk. The ceiling has to clear a real GeoLite2-City database
		// (~70 MB at time of writing) with room to grow.
		r.Body = http.MaxBytesReader(w, r.Body, maxGeoIPUploadBytes)
		// #nosec G120 -- the body is bounded by the MaxBytesReader on the line
		// above. G120 fires on any ParseMultipartForm call and does not look for
		// the guard, so it reports the mitigated case identically.
		if err := r.ParseMultipartForm(geoIPUploadMemoryBytes); err != nil {
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

		if err := os.MkdirAll("geoip", 0o750); err != nil {
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
		logger.L.LogInfo("geoip database uploaded", "path", destPath)

		// Reload the appropriate reader based on the uploaded edition. ASN and
		// Country databases use dedicated readers; anything else is treated as
		// the City/geolocation database.
		if err := reloadGeoIPByFilename(filename, destPath); err != nil {
			logger.L.LogError("failed to reload GeoIP database after upload", "error", err)
		}
	})

	mux.HandleFunc("GET /v1/geoip/status", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceMiddlewares) {
			return
		}

		exists, path, info := telemetry.GetGeoIPStatus()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exists": exists,
			"path":   path,
			"info":   info,
		})
	})

	mux.HandleFunc("POST /v1/geoip/update", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceMiddlewares) {
			return
		}

		gc := globalReg.Get(r.Context())
		var licenseKey string
		if r.Body != nil {
			var body struct {
				LicenseKey string `json:"maxmind_license_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.LicenseKey != "" {
				licenseKey = body.LicenseKey
			}
		}

		if licenseKey == "" && gc != nil && gc.Geoip != nil {
			licenseKey = gc.Geoip.MaxmindLicenseKey
		}

		if licenseKey == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("maxmind license key not configured in global settings"))
			return
		}

		err := telemetry.DownloadGeoIP(licenseKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("geoip database updated successfully"))
	})
}
