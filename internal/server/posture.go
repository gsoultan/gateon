// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/entrypoint"
	"github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	wafmw "github.com/gsoultan/gateon/internal/middleware/security/waf"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/fim"
	"github.com/gsoultan/gateon/internal/security/posture"
	"github.com/gsoultan/gateon/internal/security/siem"
	"github.com/gsoultan/gateon/internal/security/yara"
	epserver "github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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

// postureDeps is what the posture report reads: the live subsystem managers,
// and the stores the router builds route chains from.
type postureDeps struct {
	version     string
	globalStore config.GlobalConfigStore
	clamav      *security.ClamAVManager
	waf         *wafmw.WAFUpdater
	fimScanner  *fim.Scanner
	ebpf        ebpf.Manager
	routes      route.Service
	middlewares middleware.Service
	entryPoints entrypoint.Service
}

// newPostureProvider builds the GET /v1/security/posture report provider. It
// captures the live subsystem managers so each request reflects current state.
func newPostureProvider(d postureDeps) handlers.SecurityPostureProvider {
	return func(ctx context.Context) *handlers.SecurityPostureReport {
		pc := postureConfig(ctx, d)
		cov := posture.Coverage(pc)
		report := &handlers.SecurityPostureReport{
			Version:     d.version,
			GeneratedAt: time.Now(),
			WAF:         wafPosture(pc, cov, d.waf),
			ClamAV:      clamavPosture(ctx, d.globalStore, d.clamav),
			Signatures:  signaturePosture(cov),
			SIEM:        siem.CurrentStatus(),
			Ebpf:        ebpfPosture(ctx, d.globalStore, d.ebpf),
			Score:       posture.Compute(pc),
		}
		if d.fimScanner != nil {
			st := d.fimScanner.Status()
			report.FIM = &st
		}
		return report
	}
}

// postureConfig gathers the configuration the router composes chains from.
func postureConfig(ctx context.Context, d postureDeps) posture.Config {
	pc := posture.Config{Global: d.globalStore.Get(ctx)}
	if d.routes != nil {
		pc.Routes, _ = d.routes.ListPaginated(ctx, 0, 0, "", nil)
	}
	if d.middlewares != nil {
		mws, _ := d.middlewares.ListPaginated(ctx, 0, 0, "")
		pc.Middlewares = make(map[string]*gateonv1.Middleware, len(mws))
		for _, mw := range mws {
			pc.Middlewares[mw.GetId()] = mw
		}
	}
	if d.entryPoints != nil {
		pc.EntryPoints, _ = d.entryPoints.ListPaginated(ctx, 0, 0, "")
	}
	// A route WAF's mode as the WAF package builds it, so the coverage the
	// Security Hub shows and the engine that runs agree by construction.
	pc.RouteWAF = func(cfg map[string]string) posture.Mode {
		return effectiveRouteMode(wafmw.EffectiveRoute(ctx, cfg, d.globalStore))
	}
	// The gateway-wide WAF's too: its tier and category switches (ADR 0064)
	// decide which families it runs, as they do for the engine.
	pc.GlobalWAF = func() posture.Mode {
		return effectiveRouteMode(wafmw.EffectiveGlobal(ctx, d.globalStore))
	}
	mgmt := pc.Global.GetManagement()
	pc.ManagementWorldOpen = epserver.ManagementListenerWorldOpen(mgmt)
	pc.PublicManagement = managementOnEveryEntrypoint(mgmt)
	return pc
}

// effectiveRouteMode is the posture mode of a WAF -- a route's, or the
// gateway-wide one -- the engine runs as e.
// A WAF that runs no attack category refuses none of the attacks the WAF
// control is about (truth NEW-13), whatever its mode.
func effectiveRouteMode(e wafmw.Effective) posture.Mode {
	if e.Mode == wafmw.ModeOff {
		return posture.ModeOff
	}
	runsAny := false
	for _, k := range posture.AttackCategoryKeys {
		runsAny = runsAny || e.Categories[k]
	}
	switch {
	case !runsAny:
		return posture.ModeNoCategories
	case e.Mode == wafmw.ModeAuditOnly:
		return posture.ModeDetect
	default:
		return posture.ModeEnforce
	}
}

// managementOnEveryEntrypoint mirrors isPublicManagementAllowed for a request
// on a non-management entrypoint: the env override, the setting, or an
// allowed_hosts list -- which matches a Host header the client writes, so any
// client naming one of those hosts reaches the management API.
func managementOnEveryEntrypoint(mgmt *gateonv1.ManagementConfig) bool {
	return os.Getenv("GATEON_ALLOW_PUBLIC_MANAGEMENT") == "true" ||
		mgmt.GetAllowPublicManagement() || len(mgmt.GetAllowedHosts()) > 0
}

// signaturePosture reports the upload signature engine as the routes run it:
// it scans only inside a file_security middleware with enable_signature_scan
// on, so with no such route nothing is scanned, whatever the engine holds.
func signaturePosture(cov posture.RouteCoverage) handlers.SignaturePosture {
	p := handlers.SignaturePosture{Routes: cov.SignatureScanning}
	if p.Routes > 0 {
		p.Enabled = true
		p.RuleCount = yara.Default().RuleCount()
	}
	return p
}

// wafPosture reports the WAF's effective mode: the gateway-wide WAF's, and
// per route, the mode of the WAF that inspects it.
func wafPosture(pc posture.Config, cov posture.RouteCoverage, waf *wafmw.WAFUpdater) handlers.WAFPosture {
	w := pc.Global.GetWaf()
	p := handlers.WAFPosture{
		Enabled: w.GetEnabled(),
		Mode:    string(posture.GlobalMode(pc)),
		Routes:  cov,
		// auto_update_rules was repurposed: nothing downloads rules any more,
		// and the flag only loads a rules directory already on disk.
		CustomRulesFromDisk: w.GetEnabled() && w.GetAutoUpdateRules(),
	}
	if waf != nil {
		p.LastUpdated = waf.LastUpdated()
	}
	return p
}

// clamavPosture derives antivirus availability and last-scan freshness.
// Enabled reflects whether ClamAV malware scanning is actually turned on
// (WafConfig.malware_detection), NOT merely whether a Clamav config block
// exists — the default global config always populates that block, so keying
// off its presence would report "enabled" even when scanning is off.
func clamavPosture(ctx context.Context, store config.GlobalConfigStore, clamav *security.ClamAVManager) handlers.ClamAVPosture {
	var p handlers.ClamAVPosture
	if gc := store.Get(ctx); gc != nil && gc.Waf != nil {
		p.Enabled = gc.Waf.GetMalwareDetection()
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

func ebpfPosture(ctx context.Context, store config.GlobalConfigStore, ebpfManager ebpf.Manager) handlers.EbpfPosture {
	var p handlers.EbpfPosture
	if gc := store.Get(ctx); gc != nil && gc.Ebpf != nil {
		p.Enabled = gc.Ebpf.Enabled
	}
	if ebpfManager == nil {
		return p
	}
	stats, err := ebpfManager.GetMapStats()
	if err == nil {
		p.Attached = stats.Attached
		p.Interface = stats.Interface
		p.AttachMode = stats.AttachMode
		p.ShunnedIPs = stats.ShunnedIPsCount
	}
	return p
}
