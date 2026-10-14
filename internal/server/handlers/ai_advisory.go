// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/ai/llm"
	"github.com/gsoultan/gateon/internal/logger"

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

// The engines a response names. A provider's answer is named "provider:model"
// (llm.Engine).
const engineLocal = "local"

// aiAnalysisResponse is the body returned by POST /v1/AnalyzeConfig.
//
// Engine says what wrote Summary: "local", or the provider and model. Notice
// is set when a provider is configured and did not answer, saying why in
// words that carry no key, prompt or reply; Summary is then the local one.
// Insights are always the local analysis -- a model narrates them and cannot
// add, drop or reword one.
type aiAnalysisResponse struct {
	Summary  string      `json:"summary"`
	Insights []aiInsight `json:"insights"`
	Engine   string      `json:"engine"`
	Notice   string      `json:"notice,omitempty"`
}

// aiLogAnalysisResponse is the body returned by POST /v1/AnalyzeLogs.
// Local is the deterministic tally, returned beside a provider's analysis so
// the operator always sees what the lines actually say.
type aiLogAnalysisResponse struct {
	Analysis string `json:"analysis"`
	Local    string `json:"local"`
	Engine   string `json:"engine"`
	Notice   string `json:"notice,omitempty"`
}

// aiTestResponse is the body returned by POST /v1/ai-advisory/test.
type aiTestResponse struct {
	OK      bool   `json:"ok"`
	Engine  string `json:"engine,omitempty"`
	Message string `json:"message"`
}

// registerAIAdvisoryHandlers wires the Security Hub "AI Advisory" endpoints.
//
// The analysis is a dependency-free deterministic "Smart Engine" that
// inspects the live gateway configuration and recent threat telemetry
// locally. When the administrator configures a third-party model (the "ai"
// settings, ADR 0069), it is asked to narrate that analysis; whatever it
// does, the local result is computed first and is what the response carries
// when the model fails.
func registerAIAdvisoryHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	advisor := llm.NewAdvisor()
	mux.HandleFunc("POST /v1/AnalyzeConfig", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		// Body ({focus:"security"}) is advisory only; decode best-effort.
		_ = json.NewDecoder(r.Body).Decode(&struct {
			Focus string `json:"focus"`
		}{})
		cfg := liveGlobals(r.Context(), svc)
		resp := analyzeConfig(r.Context(), cfg, routeWAFCoverage(r.Context(), d, cfg))
		narrateConfig(r.Context(), advisor, cfg.GetAi(), &resp)
		writeAIJSON(w, resp)
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
		local := analyzeLogs(req.Logs)
		resp := aiLogAnalysisResponse{Analysis: local, Local: local, Engine: engineLocal}
		if len(req.Logs) > 0 {
			narrateLogs(r.Context(), advisor, liveGlobals(r.Context(), svc).GetAi(), req.Logs, &resp)
		}
		writeAIJSON(w, resp)
	})

	// The test spends a call against the stored key, so it takes the right to
	// change the settings it tests, not merely to read diagnostics.
	mux.HandleFunc("POST /v1/ai-advisory/test", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		writeAIJSON(w, testAIProvider(r.Context(), advisor, liveGlobals(r.Context(), svc).GetAi()))
	})
}

func liveGlobals(ctx context.Context, svc GlobalAndAuthAPI) *gateonv1.GlobalConfig {
	if globals := svc.GetGlobals(); globals != nil {
		return globals.Get(ctx)
	}
	return nil
}

func writeAIJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// narrateConfig replaces the local summary with the provider's, when one is
// enabled and answers.
func narrateConfig(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig, resp *aiAnalysisResponse) {
	resp.Engine = engineLocal
	if !c.GetEnabled() {
		return
	}
	findings := make([]llm.Finding, 0, len(resp.Insights))
	for _, in := range resp.Insights {
		findings = append(findings, llm.Finding{Title: in.Title, Severity: in.Severity,
			Description: in.Description, Recommendation: in.Recommendation})
	}
	text, s, err := a.Summarize(ctx, c, findings)
	if err != nil {
		resp.Notice = aiFallbackNotice(err)
		return
	}
	resp.Summary, resp.Engine = text, llm.Engine(s)
}

// narrateLogs replaces the local analysis with the provider's, when one is
// enabled and answers; the local tally stays in Local either way.
func narrateLogs(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig, lines []string, resp *aiLogAnalysisResponse) {
	if !c.GetEnabled() {
		return
	}
	text, s, err := a.AnalyzeLogs(ctx, c, resp.Local, lines)
	if err != nil {
		resp.Notice = aiFallbackNotice(err)
		return
	}
	resp.Analysis, resp.Engine = text, llm.Engine(s)
}

func testAIProvider(ctx context.Context, a *llm.Advisor, c *gateonv1.AIConfig) aiTestResponse {
	s, err := a.Test(ctx, c)
	if err != nil {
		return aiTestResponse{Message: aiFailure(err)}
	}
	return aiTestResponse{OK: true, Engine: llm.Engine(s), Message: "The provider answered."}
}

// aiFallbackNotice is what the dashboard shows above the local analysis when
// the provider did not answer.
func aiFallbackNotice(err error) string {
	return aiFailure(err) + " Showing the local analysis."
}

// aiFailure logs why a provider call failed and returns a sentence for the
// dashboard. Only the package's sentinels are named: their text carries no
// key, prompt or reply, and a transport error (which can name an internal
// address) stays in the server log.
func aiFailure(err error) string {
	for _, known := range []error{llm.ErrDisabled, llm.ErrConfig, llm.ErrAuth, llm.ErrRateLimited,
		llm.ErrRejected, llm.ErrRefused, llm.ErrBusy, llm.ErrUpstream} {
		if errors.Is(err, known) {
			if !errors.Is(known, llm.ErrDisabled) && !errors.Is(known, llm.ErrBusy) {
				logger.L.LogWarn("AI provider call failed; serving the local analysis", "error", err)
			}
			return capitalize(known.Error()) + "."
		}
	}
	logger.L.LogWarn("AI provider call failed; serving the local analysis", "error", err)
	return "The AI provider could not answer."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
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
		case posture.ModeNoCategories:
			cov.CategoriesOff = 1
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
	if cov.CategoriesOff > 0 {
		out = append(out, wafNoCategoriesInsight(cov))
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

// wafNoCategoriesInsight: a route WAF with every attack category switched off
// runs, and refuses none of SQLi, XSS, LFI or RCE (truth NEW-13).
func wafNoCategoriesInsight(cov wafCoverage) aiInsight {
	return aiInsight{
		Title: fmt.Sprintf("A WAF with every attack category off runs on %d of %d routes", cov.CategoriesOff, cov.Total),
		Description: fmt.Sprintf("On %d of %d routes the route's WAF middleware has every attack category switched off: "+
			"SQL injection, XSS, path traversal and code execution reach the backend.", cov.CategoriesOff, cov.Total),
		Severity:       insightWarning,
		Category:       categorySecurity,
		Recommendation: "Switch the categories the application needs back on in the route's WAF middleware, or remove it so the gateway-wide WAF inspects the route.",
	}
}

// wafEnableSuggestion is the config that turns the gateway-wide WAF on.
const wafEnableSuggestion = "waf:\n  enabled: true\n  paranoia_level: 1"

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

// logTally counts what a batch of log lines says. levels come from the line's
// own level; the request counts come from the status and path an access-log
// line carries, which is INFO whatever the status -- so a level count alone
// called 401s and a /.env probe healthy (truth T41).
type logTally struct {
	errors, warns, infos       int
	refused, serverErrs, probe int
	msgs                       map[string]int
}

// analyzeLogs produces a deterministic, human-readable summary of recent log
// lines (levels, refused and failed requests, probes, most frequent
// messages), without any external model.
func analyzeLogs(logs []string) string {
	if len(logs) == 0 {
		return "No logs were provided to analyze."
	}
	t := logTally{msgs: make(map[string]int)}
	for _, line := range logs {
		t.add(line)
	}
	var b strings.Builder
	b.Grow(256)
	fmt.Fprintf(&b, "Analyzed %d log lines: %d error, %d warning, %d info/other. ", len(logs), t.errors, t.warns, t.infos)
	b.WriteString(t.requestSentence())
	b.WriteString(t.verdict())
	writeTopMessages(&b, t.msgs)
	b.WriteString("(Local Mode: deterministic analysis on this server.)")
	return b.String()
}

func (t *logTally) add(line string) {
	fields := parseLogFields(line)
	level := strings.ToLower(fields["level"])
	switch {
	case level == logLevelError || (fields == nil && lineHasBareLevel(line, logLevelError, "ERROR")):
		t.errors++
	case level == "warn" || level == "warning" || (fields == nil && lineHasBareLevel(line, "warn", "WARN")):
		t.warns++
	default:
		t.infos++
	}
	switch status := fields["status"]; {
	case status == "401" || status == "403" || status == "429":
		t.refused++
	case len(status) == 3 && status[0] == '5':
		t.serverErrs++
	}
	if sensitiveProbePath(fields["path"]) {
		t.probe++
	}
	if key := extractLogMessage(line, fields); key != "" {
		t.msgs[key]++
	}
}

// logLevelError is slog's error level as a field value, lower-cased.
const logLevelError = "error"

// lineHasBareLevel reports whether an unstructured line (log.Logger's
// "2026/10/14 06:32:26 ERROR ...") names the level as a word. A structured
// line is never read this way: its level is a field, and the rest of it is
// text a client may have written.
func lineHasBareLevel(line, lower, upper string) bool {
	return strings.Contains(line, " "+lower+" ") || strings.Contains(line, " "+upper+" ")
}

// maxParsedLogLine bounds the line parseLogFields reads.
const maxParsedLogLine = 64 << 10

// parseLogFields reads the top-level fields of a slog JSON or text line, or
// returns nil for a line in neither form.
//
// The tally used to search the raw line for " status=" and " error ", and an
// access line carries the client's path before its status: a 503 to
// "/ status=200" read as served, and "/ error x" as an error. Reading fields
// the way slog wrote them -- a JSON object, or key=value pairs with quoted
// values unquoted -- leaves what the client wrote inside its own field.
func parseLogFields(line string) map[string]string {
	line = strings.TrimSpace(line)
	if len(line) > maxParsedLogLine {
		return nil
	}
	if strings.HasPrefix(line, "{") {
		return parseJSONLogFields(line)
	}
	return parseTextLogFields(line)
}

func parseJSONLogFields(line string) map[string]string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			out[k] = str
			continue
		}
		if len(v) > 0 && v[0] != '{' && v[0] != '[' {
			out[k] = string(v)
		}
	}
	return out
}

// parseTextLogFields reads slog's text form: key=value pairs separated by a
// space, a value quoted (strconv.Quote) when it holds a space, '=' or '"'.
// A line without a level field is not one slog wrote.
func parseTextLogFields(line string) map[string]string {
	out := map[string]string{}
	for line != "" {
		eq := strings.IndexByte(line, '=')
		if eq <= 0 || strings.ContainsAny(line[:eq], ` "`) {
			break
		}
		value, next, ok := cutLogValue(line[eq+1:])
		if !ok {
			break
		}
		out[line[:eq]] = value
		line = strings.TrimLeft(next, " ")
	}
	if out["level"] == "" {
		return nil
	}
	return out
}

// cutLogValue reads one value from the front of s: a quoted string, or the
// text up to the next space.
func cutLogValue(s string) (value, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		if sp := strings.IndexByte(s, ' '); sp >= 0 {
			return s[:sp], s[sp:], true
		}
		return s, "", true
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			v, err := strconv.Unquote(s[:i+1])
			return v, s[i+1:], err == nil
		}
	}
	return "", "", false
}

// sensitiveProbePaths are paths only a scanner asks for: credentials,
// repository metadata and admin consoles that are not this gateway's.
var sensitiveProbePaths = []string{
	"/.env", "/.git", "/.aws", "/.ssh", "/.htpasswd", "/etc/passwd", "/wp-login.php", "/phpmyadmin", "/server-status",
}

func sensitiveProbePath(path string) bool {
	p := strings.ToLower(path)
	for _, s := range sensitiveProbePaths {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

func (t *logTally) requestSentence() string {
	if t.refused == 0 && t.serverErrs == 0 && t.probe == 0 {
		return ""
	}
	return fmt.Sprintf("Requests: %d refused (401/403/429), %s, %s. ",
		t.refused, countOf(t.serverErrs, "server error (5xx)", "server errors (5xx)"),
		countOf(t.probe, "probe for a sensitive path", "probes for sensitive paths"))
}

// countOf is n with the noun it counts.
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (t *logTally) verdict() string {
	switch {
	case t.errors > 0 || t.serverErrs > 0:
		return "Errors are present and should be investigated first. "
	case t.refused > 0 || t.probe > 0:
		return "Requests were refused or probed for sensitive paths; check whether one client accounts for them. "
	case t.warns > 0:
		return "Warnings are present; review them for early signs of trouble. "
	default:
		return "No errors, warnings, refusals or probes detected — the gateway appears healthy. "
	}
}

// writeTopMessages appends the three most frequent messages.
func writeTopMessages(b *strings.Builder, msgCounts map[string]int) {
	type kv struct {
		msg   string
		count int
	}
	top := make([]kv, 0, len(msgCounts))
	for m, c := range msgCounts {
		top = append(top, kv{m, c})
	}
	if len(top) == 0 {
		return
	}
	slices.SortFunc(top, func(a, b kv) int {
		if a.count != b.count {
			return cmp.Compare(b.count, a.count)
		}
		return strings.Compare(a.msg, b.msg)
	})
	b.WriteString("Most frequent messages: ")
	for i := range min(3, len(top)) {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%q (×%d)", top[i].msg, top[i].count)
	}
	b.WriteString(". ")
}

// extractLogMessage is the line's msg field, or a trimmed prefix of an
// unstructured line, so similar lines group together.
func extractLogMessage(line string, fields map[string]string) string {
	if fields != nil {
		return fields["msg"]
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
