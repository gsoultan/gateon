// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/security/posture"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// aiInsight is one advisory recommendation. The JSON field names match the
// AIInsight interface consumed by ui/src/components/SecurityCenter/AIAdvisoryTab.tsx.
type aiInsight struct {
	Title           string `json:"title"`
	Description     string `json:"description"`
	Severity        string `json:"severity"` // "critical" | "warning" | "info"
	Category        string `json:"category"` // "security" | "performance" | "availability"
	Recommendation  string `json:"recommendation"`
	SuggestedConfig string `json:"suggestedConfig,omitempty"`
}

// Insight severities and categories: the vocabulary AIAdvisoryTab.tsx colours
// and picks icons by.
const (
	insightCritical      = "critical"
	insightWarning       = "warning"
	insightInfo          = "info"
	categorySecurity     = "security"
	categoryAvailability = "availability"
)

// aiAnalysisResponse is the body returned by POST /v1/AnalyzeConfig.
type aiAnalysisResponse struct {
	Summary  string      `json:"summary"`
	Insights []aiInsight `json:"insights"`
}

// aiLogAnalysisResponse is the body returned by POST /v1/AnalyzeLogs.
type aiLogAnalysisResponse struct {
	Analysis string `json:"analysis"`
}

// registerAIAdvisoryHandlers wires the Security Hub "AI Advisory" endpoints.
//
// The UI was shipping calls to POST /v1/AnalyzeConfig and POST /v1/AnalyzeLogs
// that had no backend, so the tab rendered Go's literal "404 page not found".
// These handlers implement a dependency-free deterministic "Smart Engine" that
// inspects the live gateway configuration and recent threat telemetry locally —
// no external LLM, no API keys, works offline. The UI switches to its "Local
// Mode" copy when the summary mentions "Smart Engine".
func registerAIAdvisoryHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("POST /v1/AnalyzeConfig", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		// Body ({focus:"security"}) is advisory only; decode best-effort.
		_ = json.NewDecoder(r.Body).Decode(&struct {
			Focus string `json:"focus"`
		}{})

		var cfg *gateonv1.GlobalConfig
		if globals := svc.GetGlobals(); globals != nil {
			cfg = globals.Get(r.Context())
		}
		resp := analyzeConfig(r.Context(), cfg, routeWAFCoverage(r.Context(), d, cfg))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("POST /v1/AnalyzeLogs", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		var req struct {
			Logs []string `json:"logs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aiLogAnalysisResponse{Analysis: analyzeLogs(req.Logs)})
	})
}

// analyzeConfig runs the deterministic hardening ruleset over the gateway config
// and recent threat telemetry, returning prioritized recommendations. routes
// counts the enabled routes by the mode of the WAF that inspects each.
func analyzeConfig(ctx context.Context, cfg *gateonv1.GlobalConfig, routes wafCoverage) aiAnalysisResponse {
	if cfg == nil {
		return aiAnalysisResponse{
			Summary: "Gateon Smart Engine could not read the current configuration. " +
				"Once the gateway is fully initialized, re-run the analysis for local security recommendations.",
			Insights: []aiInsight{},
		}
	}

	insights := make([]aiInsight, 0, 12)
	insights = append(insights, tlsInsights(cfg.GetTls())...)
	insights = append(insights, wafInsights(cfg.GetWaf(), routes)...)
	insights = append(insights, botInsights(routes)...)
	insights = append(insights, rateLimitInsights(routes)...)
	insights = append(insights, managementExposureInsights(cfg.GetManagement())...)
	insights = append(insights, auditInsights(cfg.GetAudit())...)
	insights = append(insights, detectionInsights(cfg)...)
	insights = append(insights, threatActivityInsights(ctx)...)

	// Order by severity so the most urgent items surface first.
	rank := map[string]int{insightCritical: 0, insightWarning: 1, insightInfo: 2}
	sort.SliceStable(insights, func(i, j int) bool {
		return rank[insights[i].Severity] < rank[insights[j].Severity]
	})
	return aiAnalysisResponse{Summary: summarizeInsights(insights), Insights: insights}
}

// tlsInsights reads min_tls_version the way the TLS manager does
// (applyExtraTLSConfig): every spelling it accepts, and TLS 1.2 when the
// setting is empty.
func tlsInsights(tlsCfg *gateonv1.TlsConfig) []aiInsight {
	if !tlsCfg.GetEnabled() || gtls.ParseTLSVersion(tlsCfg.GetMinTlsVersion(), tls.VersionTLS12) >= tls.VersionTLS12 {
		return nil
	}
	return []aiInsight{{
		Title:           "Weak minimum TLS version",
		Description:     "The minimum TLS version is below TLS 1.2, allowing legacy clients to negotiate deprecated, attackable protocol versions.",
		Severity:        insightCritical,
		Category:        categorySecurity,
		Recommendation:  "Set the minimum TLS version to TLS 1.2 (prefer TLS 1.3) on your TLS options.",
		SuggestedConfig: "tls:\n  min_tls_version: \"TLS1.2\"",
	}}
}

// wafCoverage counts the enabled HTTP routes by the mode of the WAF that
// inspects each one.
type wafCoverage = posture.RouteCoverage

// routeWAFCoverage counts the enabled routes by what inspects them. A route
// that attaches a "waf" middleware runs that WAF instead of the gateway-wide
// one, in that middleware's mode -- so a route-level audit-only WAF on a
// gateway whose global WAF enforces is a route nothing blocks for.
func routeWAFCoverage(ctx context.Context, d *Deps, global *gateonv1.GlobalConfig) wafCoverage {
	if d == nil || d.RouteService == nil || d.MwService == nil {
		return wafCoverage{}
	}
	routes, _ := d.RouteService.ListPaginated(ctx, 0, 0, "", nil)
	mws, _ := d.MwService.ListPaginated(ctx, 0, 0, "")
	byID := make(map[string]*gateonv1.Middleware, len(mws))
	for _, mw := range mws {
		byID[mw.GetId()] = mw
	}
	return posture.Coverage(posture.Config{Global: global, Routes: routes, Middlewares: byID})
}

// wafInsights reports on the WAFs the router actually runs, in the mode each
// runs in: the gateway-wide one for routes without their own, and the route's
// own WAF middleware otherwise.
//
// It used to read only the global toggle, so a gateway whose every route runs
// its own WAF was told, as its top critical finding, that no WAF was active;
// and it never read audit_only, so a WAF that blocks nothing produced no
// finding at all (T12).
func wafInsights(waf *gateonv1.WafConfig, cov wafCoverage) []aiInsight {
	if cov.Total == 0 {
		cov = wafCoverage{Total: 1}
		switch posture.GlobalWAFMode(waf) {
		case posture.ModeEnforce:
			cov.Enforcing = 1
		case posture.ModeDetect:
			cov.Detecting = 1
		default:
			cov.Off = 1
		}
	}
	if cov.Off == cov.Total {
		return []aiInsight{wafDisabledInsight()}
	}
	var out []aiInsight
	if cov.Detecting > 0 {
		out = append(out, wafAuditOnlyInsight(cov))
	}
	if cov.Off > 0 {
		out = append(out, wafPartialInsight(cov))
	}
	if waf.GetEnabled() {
		out = append(out, globalWAFInsights(waf)...)
	}
	return out
}

func wafDisabledInsight() aiInsight {
	return aiInsight{
		Title:           "Web Application Firewall is disabled",
		Description:     "No WAF is active, so common OWASP attacks (SQLi, XSS, RCE, path traversal) reach your backends unfiltered.",
		Severity:        insightCritical,
		Category:        categorySecurity,
		Recommendation:  "Enable the WAF middleware with the OWASP Core Rule Set on internet-facing routes.",
		SuggestedConfig: wafEnableSuggestion,
	}
}

// wafAuditOnlyInsight: an audit-only WAF records an attack and forwards it.
// Critical when it is all there is, since then nothing is blocked anywhere.
func wafAuditOnlyInsight(cov wafCoverage) aiInsight {
	severity := insightWarning
	if cov.Enforcing == 0 {
		severity = insightCritical
	}
	return aiInsight{
		Title: fmt.Sprintf("Web Application Firewall is detecting only (audit) on %d of %d routes", cov.Detecting, cov.Total),
		Description: fmt.Sprintf("On %d of %d routes the WAF runs audit-only: it records the attacks it matches "+
			"and forwards them to the backend. Nothing is blocked there.", cov.Detecting, cov.Total),
		Severity: severity,
		Category: categorySecurity,
		Recommendation: "Review the would-block counts on the Security Hub overview, then turn audit-only off " +
			"(globally, or on the route's WAF middleware, which replaces the global WAF on that route).",
		SuggestedConfig: "waf:\n  audit_only: false",
	}
}

func wafPartialInsight(cov wafCoverage) aiInsight {
	return aiInsight{
		Title: fmt.Sprintf("Web Application Firewall covers %d of %d routes", cov.Total-cov.Off, cov.Total),
		Description: fmt.Sprintf("%d of %d routes run no WAF, so requests to them reach their backends unfiltered.",
			cov.Off, cov.Total),
		Severity:        insightWarning,
		Category:        categorySecurity,
		Recommendation:  "Attach a WAF middleware to the remaining routes, or enable the gateway-wide WAF, which covers every route without one.",
		SuggestedConfig: wafEnableSuggestion,
	}
}

// wafEnableSuggestion is the config that turns the gateway-wide WAF on.
const wafEnableSuggestion = "waf:\n  enabled: true\n  use_crs: true\n  paranoia_level: 1"

// globalWAFInsights reviews the gateway-wide WAF's own settings.
func globalWAFInsights(waf *gateonv1.WafConfig) []aiInsight {
	var out []aiInsight
	if waf.GetParanoiaLevel() < 2 {
		out = append(out, aiInsight{
			Title:           "WAF paranoia level is low",
			Description:     "Paranoia level 1 favors low false positives but misses more sophisticated payloads.",
			Severity:        insightInfo,
			Category:        categorySecurity,
			Recommendation:  "Once you've tuned for false positives, raise the WAF paranoia level to 2 for stronger coverage.",
			SuggestedConfig: "waf:\n  paranoia_level: 2",
		})
	}
	return out
}

// rateLimitInsights reports which routes bound what one client may cost them.
// It replaces a "DoS protection is off" warning that recommended the WAF's
// dos_protection flag, which selects no rule and which ADR 0044 removed from
// the dashboard: setting it cleared the warning and protected nothing (truth
// NEW-6). A ratelimit or inflightreq middleware is what does.
func rateLimitInsights(cov wafCoverage) []aiInsight {
	if cov.Total == 0 || cov.RateLimited == cov.Total {
		return nil
	}
	title := "Rate limiting covers no route"
	if cov.RateLimited > 0 {
		title = fmt.Sprintf("Rate limiting covers %d of %d routes", cov.RateLimited, cov.Total)
	}
	return []aiInsight{{
		Title: title,
		Description: fmt.Sprintf("%d of %d routes carry no ratelimit or inflightreq middleware, so one bursty "+
			"client can use as much of their backends' capacity as it can send.", cov.Total-cov.RateLimited, cov.Total),
		Severity:       insightInfo,
		Category:       categoryAvailability,
		Recommendation: "Attach a ratelimit middleware (requests per client) or an inflightreq middleware (concurrent requests) to public routes.",
	}}
}

// botInsights reports which routes carry a bot_management middleware. It used
// to read the global bot-management switch, which only supplies defaults to
// that middleware and protects no route that lacks it, so "enabled" there was
// counted as coverage nobody had.
func botInsights(cov wafCoverage) []aiInsight {
	if cov.Total == 0 || cov.BotManagement == cov.Total {
		return nil
	}
	title := "Bot management covers no route"
	if cov.BotManagement > 0 {
		title = fmt.Sprintf("Bot management covers %d of %d routes", cov.BotManagement, cov.Total)
	}
	return []aiInsight{{
		Title: title,
		Description: fmt.Sprintf("%d of %d routes carry no bot management middleware, so automated scrapers "+
			"and credential-stuffing bots reach them unchallenged. The global bot settings are only defaults "+
			"for that middleware.", cov.Total-cov.BotManagement, cov.Total),
		Severity:       insightInfo,
		Category:       categorySecurity,
		Recommendation: "Attach a bot management middleware to sensitive routes (logins, forms, APIs).",
	}}
}

func auditInsights(audit *gateonv1.AuditConfig) []aiInsight {
	if !audit.GetEnabled() {
		return []aiInsight{{
			Title:          "Audit logging is disabled",
			Description:    "Administrative actions are not being recorded, hampering incident investigation and compliance.",
			Severity:       insightWarning,
			Category:       categorySecurity,
			Recommendation: "Enable audit logging and turn on tamper-evident entry signing.",
		}}
	}
	if !audit.GetSignEntries() {
		return []aiInsight{{
			Title:          "Audit entries are not signed",
			Description:    "Audit logging is on but entries are unsigned, so tampering cannot be detected.",
			Severity:       insightInfo,
			Category:       categorySecurity,
			Recommendation: "Enable signed audit entries (HMAC chain) for tamper evidence.",
		}}
	}
	return nil
}

// detectionInsights covers IP reputation and anomaly detection.
func detectionInsights(cfg *gateonv1.GlobalConfig) []aiInsight {
	var out []aiInsight
	if !cfg.GetSecurityAdvanced().GetIpReputation().GetEnabled() {
		out = append(out, aiInsight{
			Title:          "IP reputation filtering is off",
			Description:    "Known-malicious source IPs from threat feeds are not being pre-emptively blocked.",
			Severity:       insightInfo,
			Category:       categorySecurity,
			Recommendation: "Enable IP reputation with a reputable feed and a sensible block threshold.",
		})
	}
	if !cfg.GetAnomalyDetection().GetEnabled() {
		out = append(out, aiInsight{
			Title:          "Anomaly detection is disabled",
			Description:    "Behavioral anomalies (brute force, exploit probing, WAF-block bursts) are not being flagged or shunned.",
			Severity:       insightInfo,
			Category:       categorySecurity,
			Recommendation: "Enable anomaly detection so the correlation engine can raise incidents.",
		})
	}
	return out
}

// threatActivityInsights summarizes the threats recorded so far.
func threatActivityInsights(ctx context.Context) []aiInsight {
	total := telemetry.CountSecurityThreats(ctx, nil)
	if total <= 0 {
		return nil
	}
	types := telemetry.GetTopThreatTypes(ctx, 3)
	if len(types) == 0 {
		return nil
	}
	top := humanizeThreatType(types[0].Label)
	return []aiInsight{{
		Title: fmt.Sprintf("Recent attack activity: %s", top),
		Description: fmt.Sprintf("%d threats recorded; the most frequent type is %q. Review the Threat Explorer for source IPs and consider targeted mitigations.",
			total, top),
		Severity:       insightWarning,
		Category:       categorySecurity,
		Recommendation: "Confirm the corresponding WAF category is enabled, and block or challenge the top offending sources.",
	}}
}

// summarizeInsights is the executive summary over the ordered insights.
func summarizeInsights(insights []aiInsight) string {
	if len(insights) == 0 {
		return "Gateon Smart Engine (Local Mode) reviewed your configuration and found no high-priority hardening gaps. Your core security controls look well configured."
	}
	crit, warn := 0, 0
	for _, in := range insights {
		switch in.Severity {
		case insightCritical:
			crit++
		case insightWarning:
			warn++
		}
	}
	return fmt.Sprintf("Gateon Smart Engine (Local Mode) analyzed your gateway configuration and recent threat activity and found %d recommendation(s): %d critical, %d warning. Address critical items first.",
		len(insights), crit, warn)
}

// managementExposureInsights reports the two ways the management API ends up in
// front of any client, judged the way the listeners judge them.
//
// It used to fire only for public management with both allow-lists empty. The
// shipped allowlist is 0.0.0.0/0 and ::/0, never empty, so it could not fire,
// and it measured the wrong thing anyway: on a public entrypoint
// isPublicManagementAllowed consults neither list once public management is
// on, and allowed_hosts matches a Host header the client writes.
func managementExposureInsights(mgmt *gateonv1.ManagementConfig) []aiInsight {
	var out []aiInsight
	// GATEON_ALLOW_PUBLIC_MANAGEMENT is the override isPublicManagementAllowed
	// (internal/server) honours alongside the setting.
	if mgmt.GetAllowPublicManagement() || os.Getenv("GATEON_ALLOW_PUBLIC_MANAGEMENT") == "true" {
		out = append(out, aiInsight{
			Title: "Management API is served on every entrypoint",
			Description: "Public management is on, so the admin API and dashboard answer on every entrypoint. " +
				"management.allowed_ips applies only to the dedicated management listener, and allowed_hosts " +
				"matches a Host header the client chooses, so neither limits who reaches it there.",
			Severity:       insightCritical,
			Category:       categorySecurity,
			Recommendation: "Turn public management off and reach the dashboard through the dedicated management listener, restricted to your admin network.",
		})
	}
	if entrypoint.ManagementListenerWorldOpen(mgmt) {
		out = append(out, aiInsight{
			Title: "Management listener accepts connections from any address",
			Description: "The dedicated management listener binds to every interface and its allowlist covers the " +
				"whole address space, so the dashboard and management API face every network this host is on, " +
				"behind only the login form. Inside a container, where the container network is the boundary, this is expected.",
			Severity:       insightWarning,
			Category:       categorySecurity,
			Recommendation: "Restrict management.allowed_ips (or GATEON_MANAGEMENT_ALLOWED_IPS) to your admin network, or bind the management listener to a private address.",
		})
	}
	return out
}

// analyzeLogs produces a deterministic, human-readable summary of recent log
// lines (level breakdown + most frequent messages), without any external model.
func analyzeLogs(logs []string) string {
	if len(logs) == 0 {
		return "No logs were provided to analyze."
	}

	var errors, warns, infos int
	msgCounts := make(map[string]int)
	for _, line := range logs {
		// Avoid strings.ToLower for performance; use case-insensitive checks where possible
		// or just check for common casing in logs (slog uses level=ERROR/WARN/INFO or "level":"error")
		hasError := strings.Contains(line, "level=error") || strings.Contains(line, "level=ERROR") ||
			strings.Contains(line, "\"level\":\"error\"") || strings.Contains(line, "\"level\":\"ERROR\"") ||
			strings.Contains(line, " error ") || strings.Contains(line, " ERROR ")

		hasWarn := !hasError && (strings.Contains(line, "level=warn") || strings.Contains(line, "level=WARN") ||
			strings.Contains(line, "\"level\":\"warn\"") || strings.Contains(line, "\"level\":\"WARN\"") ||
			strings.Contains(line, " warn ") || strings.Contains(line, " WARN "))

		if hasError {
			errors++
		} else if hasWarn {
			warns++
		} else {
			infos++
		}

		if key := extractLogMessage(line); key != "" {
			msgCounts[key]++
		}
	}

	type kv struct {
		msg   string
		count int
	}
	top := make([]kv, 0, len(msgCounts))
	for m, c := range msgCounts {
		top = append(top, kv{m, c})
	}
	slices.SortFunc(top, func(a, b kv) int {
		if a.count != b.count {
			return cmp.Compare(b.count, a.count)
		}
		return strings.Compare(a.msg, b.msg)
	})

	var b strings.Builder
	b.Grow(256)
	fmt.Fprintf(&b, "Analyzed %d log lines: %d error, %d warning, %d info/other. ", len(logs), errors, warns, infos)
	switch {
	case errors == 0 && warns == 0:
		b.WriteString("No errors or warnings detected — the gateway appears healthy. ")
	case errors > 0:
		b.WriteString("Errors are present and should be investigated first. ")
	default:
		b.WriteString("Warnings are present; review them for early signs of trouble. ")
	}
	if len(top) > 0 {
		b.WriteString("Most frequent messages: ")
		limit := 3
		if len(top) < limit {
			limit = len(top)
		}
		for i := 0; i < limit; i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q (×%d)", top[i].msg, top[i].count)
		}
		b.WriteString(". ")
	}
	b.WriteString("(Local Mode: deterministic analysis, no data left this server.)")
	return b.String()
}

// extractLogMessage pulls the msg="..." field from a slog text line, falling back
// to a trimmed prefix so similar lines group together.
func extractLogMessage(line string) string {
	const marker = "msg="
	if i := strings.Index(line, marker); i >= 0 {
		rest := line[i+len(marker):]
		if strings.HasPrefix(rest, "\"") {
			if end := strings.Index(rest[1:], "\""); end >= 0 {
				return rest[1 : end+1]
			}
		}
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			return rest[:sp]
		}
		return rest
	}
	line = strings.TrimSpace(line)
	if len(line) > 60 {
		return line[:60]
	}
	return line
}

func humanizeThreatType(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return strings.ReplaceAll(s, "_", " ")
}
