package telemetry

import (
	"context"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// StartGeoIPWorker starts a background worker that periodically updates the GeoIP database.
func StartGeoIPWorker(ctx context.Context, getConfig func() *gateonv1.GlobalConfig) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial check
	runGeoIPUpdate(getConfig())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runGeoIPUpdate(getConfig())
		}
	}
}

func runGeoIPUpdate(cfg *gateonv1.GlobalConfig) {
	if cfg == nil || cfg.Geoip == nil || !cfg.Geoip.AutoUpdate || !cfg.Geoip.Enabled {
		return
	}

	if cfg.Geoip.MaxmindLicenseKey == "" {
		logger.L.Debug().Msg("skipping GeoIP auto-update: no MaxMind license key provided")
		return
	}

	// Check if update is needed based on file age
	destPath := cfg.Geoip.DbPath
	if destPath == "" {
		destPath = "geoip/GeoLite2-City.mmdb"
	}

	info, err := GetFileInfo(destPath)
	if err == nil {
		interval := time.Duration(cfg.Geoip.UpdateIntervalDays) * 24 * time.Hour
		if interval == 0 {
			interval = 30 * 24 * time.Hour
		}
		if time.Since(info.ModTime()) < interval {
			logger.L.Debug().Msg("GeoIP database is up to date")
			return
		}
	}

	logger.L.Info().Msg("starting GeoIP database auto-update")
	if err := DownloadGeoIP(cfg.Geoip.MaxmindLicenseKey); err != nil {
		logger.L.Error().Err(err).Msg("failed to auto-update GeoIP database")
	} else {
		logger.L.Info().Msg("GeoIP database auto-update successful")
	}
}

// GetFileInfo is a helper to get file info
func GetFileInfo(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
