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
				Description:     "The management API is bound to 0.0.0.0, making it accessible from any network interface. This significantly increases the attack surface of your gateway control plane.",
				Severity:        "critical",
				Category:        "security",
				Recommendation:  "Bind the management API to a specific internal IP (e.g., 127.0.0.1 or a private network IP) to prevent unauthorized external access.",
				SuggestedConfig: `{"management": {"bind": "127.0.0.1"}}`,
			})
		}
	}

	// Check Routes without Auth
	unprotectedRoutes := 0
	wildcardUnprotected := 0
	for _, r := range e.routes {
		if r.Disabled {
			continue
		}
		hasAuth := false
		for _, mwID := range r.Middlewares {
			for _, mw := range e.middlewares {
				if mw.Id == mwID && (mw.Type == "auth" || mw.Type == "jwt" || mw.Type == "paseto" || mw.Type == "oidc" || mw.Type == "forwardauth") {
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
			if strings.Contains(r.Rule, "Host(`*`)") || r.Rule == "" {
				wildcardUnprotected++
			}
		}
	}

	if wildcardUnprotected > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Wildcard routes without authentication",
			Description:    "You have routes that match any host but do not have authentication configured. This could allow unauthorized access to internal services or lead to open-proxy vulnerabilities.",
			Severity:       "critical",
			Category:       "security",
			Recommendation: "Apply an authentication middleware to all wildcard routes or restrict the 'Host' rule to specific domains.",
		})
	} else if unprotectedRoutes > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Unprotected routes detected",
			Description:    fmt.Sprintf("Found %d active routes that do not have any authentication middleware configured.", unprotectedRoutes),
			Severity:       "warning",
			Category:       "security",
			Recommendation: "Apply an authentication middleware (JWT, OIDC, or Basic Auth) to sensitive routes to ensure only authorized users can access your backends.",
		})
	}

	// Check for Security Headers
	routesWithoutSecurityHeaders := 0
	for _, r := range e.routes {
		if r.Disabled {
			continue
		}
		hasHeaders := false
		for _, mwID := range r.Middlewares {
			for _, mw := range e.middlewares {
				if mw.Id == mwID && (mw.Type == "headers" || mw.Type == "security_headers") {
					hasHeaders = true
					break
				}
			}
		}
		if !hasHeaders {
			routesWithoutSecurityHeaders++
		}
	}

	if routesWithoutSecurityHeaders > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Missing security headers",
			Description:    fmt.Sprintf("%d routes are missing standard security headers (HSTS, CSP, X-Frame-Options, etc.). This makes clients vulnerable to XSS and clickjacking.", routesWithoutSecurityHeaders),
			Severity:       "warning",
			Category:       "security",
			Recommendation: "Add a 'headers' middleware with recommended security presets and apply it to your web-facing routes.",
		})
	}

	// Check TLS Version
	if e.globals.Tls != nil && e.globals.Tls.Enabled {
		minTls := e.globals.Tls.MinTlsVersion
		if minTls == "TLS1.0" || minTls == "TLS1.1" || minTls == "" {
			insights = append(insights, &gateonv1.AIInsight{
				Title:           "Insecure TLS version",
				Description:     "Your configuration allows TLS 1.0 or 1.1, which are deprecated and have known cryptographic vulnerabilities.",
				Severity:        "high",
				Category:        "security",
				Recommendation:  "Enforce a minimum of 'TLS1.2' or 'TLS1.3' in your global TLS configuration to ensure strong encryption.",
				SuggestedConfig: `{"tls": {"min_tls_version": "TLS1.2"}}`,
			})
		}
	}

	// Check WAF
	if e.globals.Waf == nil || !e.globals.Waf.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "WAF is disabled",
			Description:     "The Web Application Firewall (WAF) is disabled globally. Your services are not protected against common OWASP Top 10 threats like SQL injection and Cross-Site Scripting (XSS).",
			Severity:        "high",
			Category:        "security",
			Recommendation:  "Enable the WAF in the global configuration and ensure it is in 'block' mode for production environments.",
			SuggestedConfig: `{"waf": {"enabled": true}}`,
		})
	}

	// Check GeoIP
	if e.globals.Geoip == nil || !e.globals.Geoip.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "GeoIP protection is disabled",
			Description:    "GeoIP-based filtering is not enabled. This prevents you from automatically blocking traffic from high-risk regions or restricting access to specific countries.",
			Severity:       "info",
			Category:       "security",
			Recommendation: "Enable GeoIP in global settings and configure country-based access policies to reduce the attack surface.",
		})
	}

	// Check Anomaly Detection
	if e.globals.AnomalyDetection == nil || !e.globals.AnomalyDetection.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Anomaly detection is disabled",
			Description:    "Real-time anomaly detection is disabled. The system cannot automatically identify and mitigate behavioral threats like credential stuffing, brute-force, or automated scanning.",
			Severity:       "high",
			Category:       "security",
			Recommendation: "Enable anomaly detection in the global configuration to provide an extra layer of defense against intelligent automated attacks.",
		})
	}

	return insights
}

func (e *LocalInsightEngine) analyzePerformance() []*gateonv1.AIInsight {
	var insights []*gateonv1.AIInsight

	// Check for Gzip/Compression
	routesWithoutCompression := 0
	for _, r := range e.routes {
		if r.Disabled {
			continue
		}
		hasCompression := false
		for _, mwID := range r.Middlewares {
			for _, mw := range e.middlewares {
				if mw.Id == mwID && (mw.Type == "compress" || mw.Type == "gzip") {
					hasCompression = true
					break
				}
			}
		}
		if !hasCompression {
			routesWithoutCompression++
		}
	}

	if routesWithoutCompression > 0 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Response compression missing",
			Description:    fmt.Sprintf("%d active routes do not have response compression enabled. This leads to higher bandwidth consumption and slower perceived performance for end-users.", routesWithoutCompression),
			Severity:       "info",
			Category:       "performance",
			Recommendation: "Apply 'compress' or 'gzip' middleware to routes serving text-based content (HTML, JS, CSS, JSON) to reduce payload size and improve load times.",
		})
	}

	// Check Redis for Caching
	if e.globals.Redis == nil || !e.globals.Redis.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "Enable Redis for peak performance",
			Description:     "Redis is currently disabled. Without Redis, Gateon uses local memory for rate limiting and caching, which is not synchronized across multiple instances and can lead to inconsistent behavior in clusters.",
			Severity:        "info",
			Category:        "performance",
			Recommendation:  "Configure and enable Redis in global settings to support distributed rate limiting, shared caching, and improved scalability.",
			SuggestedConfig: `{"redis": {"enabled": true, "addr": "localhost:6379"}}`,
		})
	}

	// Check for Rate Limiting
	routesWithoutRateLimit := 0
	activeRoutes := 0
	for _, r := range e.routes {
		if r.Disabled {
			continue
		}
		activeRoutes++
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

	if activeRoutes > 0 && routesWithoutRateLimit > activeRoutes/2 {
		insights = append(insights, &gateonv1.AIInsight{
			Title:          "Low rate limiting coverage",
			Description:    "More than half of your active routes lack rate limiting. This exposes your upstream services to resource exhaustion and potential DDoS attacks.",
			Severity:       "warning",
			Category:       "performance",
			Recommendation: "Implement rate limiting on all public endpoints to protect your infrastructure from traffic spikes and abusive clients.",
		})
	}

	// Check eBPF
	if e.globals.Ebpf == nil || !e.globals.Ebpf.Enabled {
		insights = append(insights, &gateonv1.AIInsight{
			Title:           "eBPF packet offloading disabled",
			Description:     "eBPF acceleration is not enabled. Enabling eBPF allows Gateon to process packets at the kernel level, providing near-line-rate performance and high-efficiency DDoS mitigation.",
			Severity:        "info",
			Category:        "performance",
			Recommendation:  "Enable eBPF offloading in global settings if your host kernel supports it to achieve maximum throughput and minimum latency.",
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
				Title:          fmt.Sprintf("Single point of failure: service '%s'", s.Name),
				Description:    fmt.Sprintf("The service '%s' has only one upstream target. If this target becomes unavailable, the entire service will go offline.", s.Name),
				Severity:       "high",
				Category:       "availability",
				Recommendation: "Add at least one additional upstream target and enable load balancing to ensure high availability and fault tolerance.",
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
			Title:          "Automatic health monitoring missing",
			Description:    fmt.Sprintf("%d services do not have health checks configured. Gateon cannot automatically detect or bypass unhealthy upstream servers for these services.", servicesWithoutHealthChecks),
			Severity:       "warning",
			Category:       "availability",
			Recommendation: "Configure HTTP or gRPC health checks for all services to enable automatic failover and proactive reliability management.",
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
