package handlers

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/telemetry"
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
		resp := analyzeConfig(r.Context(), cfg)
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
// and recent threat telemetry, returning prioritized recommendations.
func analyzeConfig(ctx context.Context, cfg *gateonv1.GlobalConfig) aiAnalysisResponse {
	insights := make([]aiInsight, 0, 12)

	if cfg == nil {
		return aiAnalysisResponse{
			Summary: "Gateon Smart Engine could not read the current configuration. " +
				"Once the gateway is fully initialized, re-run the analysis for local security recommendations.",
			Insights: insights,
		}
	}

	// --- TLS posture ---
	if tls := cfg.GetTls(); tls != nil && tls.GetEnabled() {
		minTLS := tls.GetMinTlsVersion()
		if minTLS == "" || strings.Contains(minTLS, "1.0") || strings.Contains(minTLS, "1.1") {
			insights = append(insights, aiInsight{
				Title:           "Weak minimum TLS version",
				Description:     "The minimum TLS version is unset or below TLS 1.2, allowing legacy clients to negotiate deprecated, attackable protocol versions.",
				Severity:        "critical",
				Category:        "security",
				Recommendation:  "Set the minimum TLS version to TLS 1.2 (prefer TLS 1.3) on your TLS options.",
				SuggestedConfig: "tls:\n  min_tls_version: \"TLS1.2\"",
			})
		}
	}

	// --- WAF posture ---
	waf := cfg.GetWaf()
	if waf == nil || !waf.GetEnabled() {
		insights = append(insights, aiInsight{
			Title:           "Web Application Firewall is disabled",
			Description:     "No WAF is active, so common OWASP attacks (SQLi, XSS, RCE, path traversal) reach your backends unfiltered.",
			Severity:        "critical",
			Category:        "security",
			Recommendation:  "Enable the WAF middleware with the OWASP Core Rule Set on internet-facing routes.",
			SuggestedConfig: "waf:\n  enabled: true\n  use_crs: true\n  paranoia_level: 1",
		})
	} else {
		if waf.GetParanoiaLevel() < 2 {
			insights = append(insights, aiInsight{
				Title:           "WAF paranoia level is low",
				Description:     "Paranoia level 1 favors low false positives but misses more sophisticated payloads.",
				Severity:        "info",
				Category:        "security",
				Recommendation:  "Once you've tuned for false positives, raise the WAF paranoia level to 2 for stronger coverage.",
				SuggestedConfig: "waf:\n  paranoia_level: 2",
			})
		}
		if !waf.GetDosProtection() {
			insights = append(insights, aiInsight{
				Title:          "DoS protection is off",
				Description:    "WAF DoS protection is disabled; bursty abusive clients can exhaust backend capacity.",
				Severity:       "warning",
				Category:       "availability",
				Recommendation: "Enable WAF DoS protection (and consider eBPF/XDP rate limiting) on public entrypoints.",
			})
		}
		if bm := waf.GetBotManagement(); bm == nil || !bm.GetEnabled() {
			insights = append(insights, aiInsight{
				Title:          "Bot management is disabled",
				Description:    "Automated scrapers and credential-stuffing bots are not being challenged.",
				Severity:       "info",
				Category:       "security",
				Recommendation: "Enable bot management with a JS/browser-integrity challenge for sensitive routes.",
			})
		}
	}

	// --- Management plane exposure ---
	if mgmt := cfg.GetManagement(); mgmt != nil && mgmt.GetAllowPublicManagement() {
		if len(mgmt.GetAllowedIps()) == 0 && len(mgmt.GetAllowedHosts()) == 0 {
			insights = append(insights, aiInsight{
				Title:          "Management API exposed publicly without an allow-list",
				Description:    "Public management access is enabled but no allowed IPs or hosts are configured, exposing the admin API/dashboard to the internet.",
				Severity:       "critical",
				Category:       "security",
				Recommendation: "Restrict management access with an IP/CIDR allow-list (and/or allowed hosts), or disable public management.",
			})
		}
	}

	// --- Audit logging ---
	if audit := cfg.GetAudit(); audit == nil || !audit.GetEnabled() {
		insights = append(insights, aiInsight{
			Title:          "Audit logging is disabled",
			Description:    "Administrative actions are not being recorded, hampering incident investigation and compliance.",
			Severity:       "warning",
			Category:       "security",
			Recommendation: "Enable audit logging and turn on tamper-evident entry signing.",
		})
	} else if !audit.GetSignEntries() {
		insights = append(insights, aiInsight{
			Title:          "Audit entries are not signed",
			Description:    "Audit logging is on but entries are unsigned, so tampering cannot be detected.",
			Severity:       "info",
			Category:       "security",
			Recommendation: "Enable signed audit entries (HMAC chain) for tamper evidence.",
		})
	}

	// --- IP reputation / anomaly detection ---
	if sa := cfg.GetSecurityAdvanced(); sa == nil || sa.GetIpReputation() == nil || !sa.GetIpReputation().GetEnabled() {
		insights = append(insights, aiInsight{
			Title:          "IP reputation filtering is off",
			Description:    "Known-malicious source IPs from threat feeds are not being pre-emptively blocked.",
			Severity:       "info",
			Category:       "security",
			Recommendation: "Enable IP reputation with a reputable feed and a sensible block threshold.",
		})
	}
	if ad := cfg.GetAnomalyDetection(); ad == nil || !ad.GetEnabled() {
		insights = append(insights, aiInsight{
			Title:          "Anomaly detection is disabled",
			Description:    "Behavioral anomalies (brute force, exploit probing, impossible travel) are not being flagged.",
			Severity:       "info",
			Category:       "security",
			Recommendation: "Enable anomaly detection so the correlation engine can raise incidents.",
		})
	}

	// --- Observed threat telemetry ---
	if total := telemetry.CountSecurityThreats(ctx); total > 0 {
		if types := telemetry.GetTopThreatTypes(ctx, 3); len(types) > 0 {
			top := types[0]
			insights = append(insights, aiInsight{
				Title: fmt.Sprintf("Recent attack activity: %s", humanizeThreatType(top.Label)),
				Description: fmt.Sprintf("%d threats recorded; the most frequent type is %q. Review the Threat Explorer for source IPs and consider targeted mitigations.",
					total, humanizeThreatType(top.Label)),
				Severity:       "warning",
				Category:       "security",
				Recommendation: "Confirm the corresponding WAF category is enabled, and block or challenge the top offending sources.",
			})
		}
	}

	// Order by severity so the most urgent items surface first.
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(insights, func(i, j int) bool {
		return rank[insights[i].Severity] < rank[insights[j].Severity]
	})

	crit, warn := 0, 0
	for _, in := range insights {
		switch in.Severity {
		case "critical":
			crit++
		case "warning":
			warn++
		}
	}

	var summary string
	switch {
	case len(insights) == 0:
		summary = "Gateon Smart Engine (Local Mode) reviewed your configuration and found no high-priority hardening gaps. Your core security controls look well configured."
	default:
		summary = fmt.Sprintf("Gateon Smart Engine (Local Mode) analyzed your gateway configuration and recent threat activity and found %d recommendation(s): %d critical, %d warning. Address critical items first.",
			len(insights), crit, warn)
	}

	return aiAnalysisResponse{Summary: summary, Insights: insights}
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
