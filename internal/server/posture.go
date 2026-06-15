package server

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/fim"
	"github.com/gsoultan/gateon/internal/security/yara"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/internal/syncutil"
)

// Environment variables controlling File Integrity Monitoring. FIM is opt-in:
// it activates only when GATEON_FIM_PATHS lists at least one path.
const (
	envFIMPaths    = "GATEON_FIM_PATHS"    // OS-path-list separated, files/dirs to monitor
	envFIMInterval = "GATEON_FIM_INTERVAL" // Go duration, e.g. "10m"
)

// startFIM creates and launches the File Integrity Monitor when configured via
// GATEON_FIM_PATHS. It returns the running scanner (or nil when FIM is disabled
// or misconfigured) so the posture report can surface its status.
func startFIM(ctx context.Context, wg *syncutil.WaitGroup) *fim.Scanner {
	paths := parsePathList(os.Getenv(envFIMPaths))
	if len(paths) == 0 {
		return nil
	}

	scanner, err := fim.New(fim.Config{
		Paths:    paths,
		Interval: parseDuration(os.Getenv(envFIMInterval)),
		OnDrift:  logFIMDrift,
	})
	if err != nil {
		logger.L.LogError("failed to start file integrity monitor", "error", err)
		return nil
	}

	logger.L.LogInfo("file integrity monitoring enabled", "paths", paths)
	wg.Go(func() { scanner.Start(ctx) })
	return scanner
}

// logFIMDrift records detected integrity changes as warnings so they are
// captured by the audit/log pipeline and visible to operators.
func logFIMDrift(events []fim.Event) {
	for _, e := range events {
		logger.L.LogWarn("file integrity drift detected",
			"path", e.Path, "change", string(e.Change))
	}
}

// parsePathList splits an OS-path-list (':' on Unix, ';' on Windows) and
// trims/drops empty entries.
func parsePathList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, string(os.PathListSeparator))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseDuration parses a Go duration string, returning 0 (use FIM defaults) on
// empty or invalid input.
func parseDuration(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logger.L.LogWarn("invalid FIM interval, using default", "value", raw, "error", err)
		return 0
	}
	return d
}

// newPostureProvider builds the GET /v1/security/posture report provider. It
// captures the live subsystem managers so each request reflects current state.
func newPostureProvider(
	version string,
	globalStore config.GlobalConfigStore,
	clamav *security.ClamAVManager,
	waf *middleware.WAFUpdater,
	fimScanner *fim.Scanner,
) handlers.SecurityPostureProvider {
	return func(ctx context.Context) *handlers.SecurityPostureReport {
		report := &handlers.SecurityPostureReport{
			Version:     version,
			GeneratedAt: time.Now(),
			WAF:         wafPosture(ctx, globalStore, waf),
			ClamAV:      clamavPosture(ctx, globalStore, clamav),
			Signatures: handlers.SignaturePosture{
				Enabled:   true,
				RuleCount: yara.Default().RuleCount(),
			},
		}
		if fimScanner != nil {
			st := fimScanner.Status()
			report.FIM = &st
		}
		return report
	}
}

// wafPosture derives WAF freshness from config + the updater's status file.
func wafPosture(ctx context.Context, store config.GlobalConfigStore, waf *middleware.WAFUpdater) handlers.WAFPosture {
	var p handlers.WAFPosture
	if gc := store.Get(ctx); gc != nil && gc.Waf != nil {
		p.Enabled = gc.Waf.GetEnabled()
		p.AutoUpdate = gc.Waf.GetAutoUpdateRules()
	}
	if waf != nil {
		p.LastUpdated = waf.LastUpdated()
	}
	return p
}

// clamavPosture derives antivirus availability and last-scan freshness.
func clamavPosture(ctx context.Context, store config.GlobalConfigStore, clamav *security.ClamAVManager) handlers.ClamAVPosture {
	var p handlers.ClamAVPosture
	if gc := store.Get(ctx); gc != nil && gc.Waf != nil && gc.Waf.GetClamav() != nil {
		p.Enabled = true
	}
	if clamav == nil {
		return p
	}
	p.Installed = clamav.IsInstalled(ctx)
	status := clamav.GetScanStatus()
	p.LastScan = status.LastScan
	p.LastResult = status.LastResult
	p.LastError = status.LastError
	return p
}
