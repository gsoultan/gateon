package ai

import (
	"context"
	"fmt"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// LocalInsightEngine provides rule-based insights without external AI.
type LocalInsightEngine struct {
	globals     *gateonv1.GlobalConfig
	routes      []*gateonv1.Route
	services    []*gateonv1.Service
	middlewares []*gateonv1.Middleware
	entrypoints []*gateonv1.EntryPoint
}

func NewLocalInsightEngine(globals *gateonv1.GlobalConfig, routes []*gateonv1.Route, services []*gateonv1.Service, middlewares []*gateonv1.Middleware, entrypoints []*gateonv1.EntryPoint) *LocalInsightEngine {
	return &LocalInsightEngine{
		globals:     globals,
		routes:      routes,
		services:    services,
		middlewares: middlewares,
		entrypoints: entrypoints,
	}
}

func (e *LocalInsightEngine) Analyze(ctx context.Context) ([]*gateonv1.AIInsight, string) {
	var insights []*gateonv1.AIInsight

	// 1. Security Analysis
	insights = append(insights, e.analyzeSecurity()...)

	// 2. Performance Analysis
	insights = append(insights, e.analyzePerformance()...)

	// 3. Availability Analysis
	insights = append(insights, e.analyzeAvailability()...)

	summary := fmt.Sprintf("Local analysis completed. Identified %d potential optimizations across security, performance, and availability.", len(insights))
	if len(insights) == 0 {
		summary = "Your configuration follows all local best practices. No immediate optimizations found."
	}

	return insights, summary
}

func (e *LocalInsightEngine) analyzeSecurity() []*gateonv1.AIInsight {
	var insights []*gateonv1.AIInsight

	// Check Management Security
	if e.globals.Management != nil {
		if e.globals.Management.Bind == "0.0.0.0" && !e.globals.Management.AllowPublicManagement {
			insights = append(insights, &gateonv1.AIInsight{
				Title:           "Management API exposed on all interfaces",
				Description:     "The management API is bound to 0.0.0.0, which makes it accessible from any network interface. This is a security risk if not properly firewalled.",
				Severity:        "critical",
				Category:        "security",
				Recommendation:  "Bind the management API to a specific internal IP (e.g., 127.0.0.1 or a private network IP).",
				SuggestedConfig: `{"management": {"bind": "127.0.0.1"}}`,
			})
		}
	}

	// Check Routes without Auth
	unprotectedRoutes := 0
	for _, r := range e.routes {
		hasAuth := false
		for _, mwID := range r.Middlewares {
			for _, mw := range e.middlewares {
				if mw.Id == mwID && (mw.Type == "auth" || mw.Type == "jwt" || mw.Type == "paseto" || mw.Type == "oidc") {
					hasAuth = true
					break
				}
			}
			if hasAuth {
				break
			}
		}
		if !hasAuth {
			unprotectedRoutes++
		}
	}

	if unprotectedRoutes > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Unprotected routes detected",
			Description:    fmt.Sprintf("Found %d routes that do not have any authentication middleware configured.", unprotectedRoutes),
			Severity:       "warning",
			Category:       "security",
			Recommendation: "Apply an authentication middleware (JWT, OIDC, or Basic Auth) to sensitive routes.",
		})
	}

	// Check TLS Version
	if e.globals.Tls != nil && e.globals.Tls.Enabled {
		minTls := e.globals.Tls.MinTlsVersion
		if minTls == "TLS1.0" || minTls == "TLS1.1" || minTls == "" {
			insights = append(insights, &gateonv1.AIInsight{
				Title:           "Insecure TLS version",
				Description:     "Your configuration allows TLS 1.0 or 1.1, which are deprecated and considered insecure.",
				Severity:        "warning",
				Category:        "security",
				Recommendation:  "Set 'min_tls_version' to 'TLS1.2' or 'TLS1.3' in your TLS configuration.",
				SuggestedConfig: `{"tls": {"min_tls_version": "TLS1.2"}}`,
			})
		}
	}

	// Check WAF
	if e.globals.Waf == nil || !e.globals.Waf.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "WAF is disabled",
			Description:     "The Web Application Firewall (WAF) is disabled globally. This leaves your services vulnerable to common attacks like SQLi and XSS.",
			Severity:        "high",
			Category:        "security",
			Recommendation:  "Enable the WAF in the global configuration.",
			SuggestedConfig: `{"waf": {"enabled": true}}`,
		})
	}

	// Check GeoIP
	if e.globals.Geoip == nil || !e.globals.Geoip.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "GeoIP protection is disabled",
			Description:    "GeoIP-based filtering is not enabled. Enabling it allows you to block traffic from high-risk countries at the edge.",
			Severity:       "info",
			Category:       "security",
			Recommendation: "Enable and configure GeoIP in the global settings.",
		})
	}

	// Check Anomaly Detection
	if e.globals.AnomalyDetection == nil || !e.globals.AnomalyDetection.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Anomaly detection is disabled",
			Description:    "Real-time anomaly detection is disabled. This prevents the system from automatically identifying and mitigating behavioral threats like brute-force and exploit scanning.",
			Severity:       "high",
			Category:       "security",
			Recommendation: "Enable anomaly detection in the global configuration.",
		})
	}

	return insights
}

func (e *LocalInsightEngine) analyzePerformance() []*gateonv1.AIInsight {
	var insights []*gateonv1.AIInsight

	// Check for Gzip/Compression
	hasCompression := false
	for _, mw := range e.middlewares {
		if mw.Type == "compress" || mw.Type == "gzip" {
			hasCompression = true
			break
		}
	}

	if !hasCompression {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Enable response compression",
			Description:    "None of your middlewares provide response compression. This can lead to higher bandwidth usage and slower load times for clients.",
			Severity:       "info",
			Category:       "performance",
			Recommendation: "Add a 'compress' middleware and apply it to routes serving text-based content.",
		})
	}

	// Check Redis for Caching
	if e.globals.Redis == nil || !e.globals.Redis.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "Enable Redis for better performance",
			Description:     "Redis is currently disabled. Enabling Redis allows for distributed rate limiting, caching, and better overall performance in a clustered environment.",
			Severity:        "info",
			Category:        "performance",
			Recommendation:  "Configure and enable Redis in the global settings.",
			SuggestedConfig: `{"redis": {"enabled": true, "addr": "localhost:6379"}}`,
		})
	}

	// Check for Rate Limiting
	routesWithoutRateLimit := 0
	for _, r := range e.routes {
		hasRateLimit := false
		for _, mwID := range r.Middlewares {
			for _, mw := range e.middlewares {
				if mw.Id == mwID && (mw.Type == "ratelimit" || mw.Type == "throttling") {
					hasRateLimit = true
					break
				}
			}
		}
		if !hasRateLimit {
			routesWithoutRateLimit++
		}
	}

	if routesWithoutRateLimit > len(e.routes)/2 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Incomplete rate limiting coverage",
			Description:    "More than half of your routes lack rate limiting. This increases the risk of resource exhaustion during traffic spikes.",
			Severity:       "warning",
			Category:       "performance",
			Recommendation: "Apply rate limiting middlewares to your most frequently accessed routes.",
		})
	}

	// Check eBPF
	if e.globals.Ebpf == nil || !e.globals.Ebpf.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "eBPF offloading is disabled",
			Description:     "eBPF is not enabled. Enabling eBPF provides kernel-level protection against DDoS and significantly improves performance by offloading packet processing.",
			Severity:        "info",
			Category:        "performance",
			Recommendation:  "Enable eBPF offloading in the global configuration.",
			SuggestedConfig: `{"ebpf": {"enabled": true, "xdp_rate_limit": true, "xdp_ip_shunning": true}}`,
		})
	}

	return insights
}

func (e *LocalInsightEngine) analyzeAvailability() []*gateonv1.AIInsight {
	var insights []*gateonv1.AIInsight

	// Check Service Upstreams
	for _, s := range e.services {
		if len(s.WeightedTargets) == 1 {
			insights = append(insights, &gateonv1.AIInsight{
				Title:          fmt.Sprintf("Single point of failure for service '%s'", s.Name),
				Description:    fmt.Sprintf("Service '%s' has only one upstream server. If this server goes down, the service will be unavailable.", s.Name),
				Severity:       "warning",
				Category:       "availability",
				Recommendation: "Add at least one more upstream server for redundancy and enable load balancing.",
			})
		}
	}

	// Check Health Checks
	servicesWithoutHealthChecks := 0
	for _, s := range e.services {
		if s.HealthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED {
			servicesWithoutHealthChecks++
		}
	}

	if servicesWithoutHealthChecks > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Missing health checks",
			Description:    fmt.Sprintf("%d services do not have health checks enabled. Gateon cannot automatically skip unhealthy upstreams for these services.", servicesWithoutHealthChecks),
			Severity:       "info",
			Category:       "availability",
			Recommendation: "Configure health check endpoints for your services to improve resilience.",
		})
	}

	return insights
}

func (e *LocalInsightEngine) AnalyzeLogs(logs []string) (string, []*gateonv1.AIInsight) {
	var insights []*gateonv1.AIInsight
	errorCount := 0
	wafBlockCount := 0
	upstreamErrorCount := 0

	for _, log := range logs {
		lowLog := strings.ToLower(log)
		if strings.Contains(lowLog, "error") || strings.Contains(lowLog, "fail") {
			errorCount++
		}
		if strings.Contains(lowLog, "waf") && (strings.Contains(lowLog, "block") || strings.Contains(lowLog, "deny")) {
			wafBlockCount++
		}
		if strings.Contains(lowLog, "upstream") && (strings.Contains(lowLog, "timeout") || strings.Contains(lowLog, "refused") || strings.Contains(lowLog, "502") || strings.Contains(lowLog, "504")) {
			upstreamErrorCount++
		}
	}

	analysis := "Log analysis shows a healthy system with no significant issues."
	if errorCount > len(logs)/5 {
		analysis = fmt.Sprintf("High error rate detected in logs (%d/%d lines).", errorCount, len(logs))
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "High error rate detected",
			Description:    "A significant portion of recent logs contains error messages.",
			Severity:       "warning",
			Category:       "availability",
			Recommendation: "Check the service health status and upstream logs for systemic failures.",
		})
	}

	if wafBlockCount > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Active WAF blocking",
			Description:    fmt.Sprintf("Detected %d instances of WAF blocking malicious requests in the logs.", wafBlockCount),
			Severity:       "info",
			Category:       "security",
			Recommendation: "Review WAF logs to identify potential ongoing attack patterns.",
		})
	}

	if upstreamErrorCount > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Upstream connectivity issues",
			Description:    "Logs indicate timeouts or connection refusals when reaching upstream services.",
			Severity:       "high",
			Category:       "availability",
			Recommendation: "Verify that upstream services are running and accessible from the Gateon instance. Check network/firewall rules.",
		})
	}

	return analysis, insights
}
