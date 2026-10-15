// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sort"

	"github.com/gsoultan/gateon/internal/security/posture"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// analyzeConfig runs the deterministic hardening ruleset over the gateway config
// and recent threat telemetry, returning prioritized recommendations.
func analyzeConfig(ctx context.Context, g Gateway) ConfigAnalysis {
	cfg, routes := g.Config, g.Routes
	if cfg == nil {
		return ConfigAnalysis{
			Summary: "Gateon Smart Engine could not read the current configuration. " +
				"Once the gateway is fully initialized, re-run the analysis for local security recommendations.",
			Insights: []Insight{},
		}
	}

	insights := make([]Insight, 0, 12)
	insights = append(insights, tlsInsights(cfg.GetTls())...)
	insights = append(insights, wafInsights(cfg.GetWaf(), routes)...)
	insights = append(insights, botInsights(routes)...)
	insights = append(insights, rateLimitInsights(routes)...)
	insights = append(insights, managementExposureInsights(cfg.GetManagement(), g.ManagementWorldOpen)...)
	insights = append(insights, auditInsights(cfg.GetAudit())...)
	insights = append(insights, detectionInsights(cfg)...)
	insights = append(insights, threatActivityInsights(ctx)...)

	// Order by severity so the most urgent items surface first.
	rank := map[string]int{insightCritical: 0, insightWarning: 1, insightInfo: 2}
	sort.SliceStable(insights, func(i, j int) bool {
		return rank[insights[i].Severity] < rank[insights[j].Severity]
	})
	return ConfigAnalysis{Summary: summarizeInsights(insights), Insights: insights}
}

// tlsInsights reads min_tls_version the way the TLS manager does
// (applyExtraTLSConfig): every spelling it accepts, and TLS 1.2 when the
// setting is empty.
func tlsInsights(tlsCfg *gateonv1.TlsConfig) []Insight {
	if !tlsCfg.GetEnabled() || gtls.ParseTLSVersion(tlsCfg.GetMinTlsVersion(), tls.VersionTLS12) >= tls.VersionTLS12 {
		return nil
	}
	return []Insight{{
		Title:           "Weak minimum TLS version",
		Description:     "The minimum TLS version is below TLS 1.2, allowing legacy clients to negotiate deprecated, attackable protocol versions.",
		Severity:        insightCritical,
		Category:        categorySecurity,
		Recommendation:  "Set the minimum TLS version to TLS 1.2 (prefer TLS 1.3) on your TLS options.",
		SuggestedConfig: "tls:\n  min_tls_version: \"TLS1.2\"",
	}}
}

// wafInsights reports on the WAFs the router actually runs, in the mode each
// runs in: the gateway-wide one for routes without their own, and the route's
// own WAF middleware otherwise.
//
// It used to read only the global toggle, so a gateway whose every route runs
// its own WAF was told, as its top critical finding, that no WAF was active;
// and it never read audit_only, so a WAF that blocks nothing produced no
// finding at all (T12).
func wafInsights(waf *gateonv1.WafConfig, cov Coverage) []Insight {
	if cov.Total == 0 {
		cov = Coverage{Total: 1}
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
		return []Insight{wafDisabledInsight()}
	}
	var out []Insight
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

func wafDisabledInsight() Insight {
	return Insight{
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
func wafAuditOnlyInsight(cov Coverage) Insight {
	severity := insightWarning
	if cov.Enforcing == 0 {
		severity = insightCritical
	}
	return Insight{
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

func wafPartialInsight(cov Coverage) Insight {
	return Insight{
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
func wafNoCategoriesInsight(cov Coverage) Insight {
	return Insight{
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
func globalWAFInsights(waf *gateonv1.WafConfig) []Insight {
	var out []Insight
	if waf.GetParanoiaLevel() < 2 {
		out = append(out, Insight{
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
func rateLimitInsights(cov Coverage) []Insight {
	if cov.Total == 0 || cov.RateLimited == cov.Total {
		return nil
	}
	title := "Rate limiting covers no route"
	if cov.RateLimited > 0 {
		title = fmt.Sprintf("Rate limiting covers %d of %d routes", cov.RateLimited, cov.Total)
	}
	return []Insight{{
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
func botInsights(cov Coverage) []Insight {
	if cov.Total == 0 || cov.BotManagement == cov.Total {
		return nil
	}
	title := "Bot management covers no route"
	if cov.BotManagement > 0 {
		title = fmt.Sprintf("Bot management covers %d of %d routes", cov.BotManagement, cov.Total)
	}
	return []Insight{{
		Title: title,
		Description: fmt.Sprintf("%d of %d routes carry no bot management middleware, so automated scrapers "+
			"and credential-stuffing bots reach them unchallenged. The global bot settings are only defaults "+
			"for that middleware.", cov.Total-cov.BotManagement, cov.Total),
		Severity:       insightInfo,
		Category:       categorySecurity,
		Recommendation: "Attach a bot management middleware to sensitive routes (logins, forms, APIs).",
	}}
}

func auditInsights(audit *gateonv1.AuditConfig) []Insight {
	if !audit.GetEnabled() {
		return []Insight{{
			Title:          "Audit logging is disabled",
			Description:    "Administrative actions are not being recorded, hampering incident investigation and compliance.",
			Severity:       insightWarning,
			Category:       categorySecurity,
			Recommendation: "Enable audit logging and turn on tamper-evident entry signing.",
		}}
	}
	if !audit.GetSignEntries() {
		return []Insight{{
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
func detectionInsights(cfg *gateonv1.GlobalConfig) []Insight {
	var out []Insight
	if !cfg.GetSecurityAdvanced().GetIpReputation().GetEnabled() {
		out = append(out, Insight{
			Title:          "IP reputation filtering is off",
			Description:    "Known-malicious source IPs from threat feeds are not being pre-emptively blocked.",
			Severity:       insightInfo,
			Category:       categorySecurity,
			Recommendation: "Enable IP reputation with a reputable feed and a sensible block threshold.",
		})
	}
	if !cfg.GetAnomalyDetection().GetEnabled() {
		out = append(out, Insight{
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
func threatActivityInsights(ctx context.Context) []Insight {
	total := telemetry.CountSecurityThreats(ctx, nil)
	if total <= 0 {
		return nil
	}
	types := telemetry.GetTopThreatTypes(ctx, 3)
	if len(types) == 0 {
		return nil
	}
	top := humanizeThreatType(types[0].Label)
	return []Insight{{
		Title: fmt.Sprintf("Recent attack activity: %s", top),
		Description: fmt.Sprintf("%d threats recorded; the most frequent type is %q. Review the Threat Explorer for source IPs and consider targeted mitigations.",
			total, top),
		Severity:       insightWarning,
		Category:       categorySecurity,
		Recommendation: "Confirm the corresponding WAF category is enabled, and block or challenge the top offending sources.",
	}}
}

// summarizeInsights is the executive summary over the ordered insights.
func summarizeInsights(insights []Insight) string {
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
func managementExposureInsights(mgmt *gateonv1.ManagementConfig, listenerWorldOpen bool) []Insight {
	var out []Insight
	// GATEON_ALLOW_PUBLIC_MANAGEMENT is the override isPublicManagementAllowed
	// (internal/server) honours alongside the setting.
	if mgmt.GetAllowPublicManagement() || os.Getenv("GATEON_ALLOW_PUBLIC_MANAGEMENT") == "true" {
		out = append(out, Insight{
			Title: "Management API is served on every entrypoint",
			Description: "Public management is on, so the admin API and dashboard answer on every entrypoint. " +
				"management.allowed_ips applies only to the dedicated management listener, and allowed_hosts " +
				"matches a Host header the client chooses, so neither limits who reaches it there.",
			Severity:       insightCritical,
			Category:       categorySecurity,
			Recommendation: "Turn public management off and reach the dashboard through the dedicated management listener, restricted to your admin network.",
		})
	}
	if listenerWorldOpen {
		out = append(out, Insight{
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
