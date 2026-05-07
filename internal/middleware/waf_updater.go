package middleware

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

// WAFUpdater handles periodic updates of WAF rules.
type WAFUpdater struct {
	globalStore config.GlobalConfigStore
	rulesPath   string
}

// NewWAFUpdater creates a new WAFUpdater.
func NewWAFUpdater(globalStore config.GlobalConfigStore, rulesPath string) *WAFUpdater {
	return &WAFUpdater{
		globalStore: globalStore,
		rulesPath:   rulesPath,
	}
}

// Start starts the periodic update process.
func (u *WAFUpdater) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Initial check
	u.checkAndUpdate()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkAndUpdate()
		}
	}
}

func (u *WAFUpdater) checkAndUpdate() {
	u.PerformUpdate(false)
}

// PerformUpdate runs the update process. If force is true, it ignores the interval.
func (u *WAFUpdater) PerformUpdate(force bool) error {
	global := u.globalStore.Get(context.Background())
	if global == nil || global.Waf == nil || (!global.Waf.AutoUpdateRules && !force) {
		return nil
	}

	interval := time.Duration(global.Waf.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	rulesUrl := global.Waf.RulesUrl
	if rulesUrl == "" {
		// Default to OWASP CRS v4.0.0
		rulesUrl = "https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.zip"
	}

	rulesDir := filepath.Join(u.rulesPath, "rules")
	statusFile := filepath.Join(u.rulesPath, "last_update.txt")

	lastUpdate := time.Time{}
	if data, err := os.ReadFile(statusFile); err == nil {
		lastUpdate, _ = time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	}

	if !force && time.Since(lastUpdate) < interval {
		return nil
	}

	logger.L.Info().Str("url", rulesUrl).Msg("Updating WAF rules...")

	if err := u.downloadAndExtract(rulesUrl, rulesDir); err != nil {
		logger.L.Error().Err(err).Msg("Failed to update WAF rules")
		return err
	}

	_ = os.WriteFile(statusFile, []byte(time.Now().Format(time.RFC3339)), 0644)
	logger.L.Info().Msg("WAF rules updated successfully")

	// Invalidate cache to apply new rules
	InvalidateWAFCache()
	return nil
}

func (u *WAFUpdater) downloadAndExtract(url string, destDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	tmpFile := filepath.Join(os.TempDir(), "waf_rules.zip")
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return err
	}
	out.Close()

	return u.unzip(tmpFile, destDir)
}

func (u *WAFUpdater) unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}

	for _, f := range r.File {
		// Skip the top-level directory in the ZIP if it exists
		parts := strings.Split(f.Name, "/")
		if len(parts) <= 1 {
			continue
		}

		// Map back to the expected structure (@owasp_crs/...)
		// The zip usually has a prefix like "coreruleset-4.0.0/"
		relPath := filepath.Join(parts[1:]...)
		if relPath == "" {
			continue
		}

		fpath := filepath.Join(dest, relPath)

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	// Coraza expects rules under @owasp_crs, but we map @ to the RootFS.
	// So we need a folder named owasp_crs inside our destDir.
	// Wait, if we use RootFS(os.DirFS(destDir)), then "Include @owasp_crs/..." will look for "owasp_crs/..." in destDir.

	return nil
}
