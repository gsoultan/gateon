// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/rules"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// WAFConfig configures the WAF middleware.
type WAFConfig struct {
	ParanoiaLevel   int    // CRS paranoia level 1-4 (default 1)
	DirectivesFile  string // Optional path to custom directives file
	TrustCloudflare bool   // Use CF-Connecting-IP for REMOTE_ADDR in request
	AuditOnly       bool   // If true, log matches but do not block (detection-only mode)

	// AllowedMethods is the HTTP method allowlist. Empty means the default set.
	// It replaces the SecLang tx.allowed_methods variable that the directive
	// preamble used to seed for CRS rule 911.
	AllowedMethods map[string]bool

	// DisableProtocolChecks turns off the request-level protocol enforcement
	// that replaced CRS rules 911 and 920.
	DisableProtocolChecks bool

	// FailOpen permits a request the engine could not fully analyse — one that
	// exhausted its inspection budget, exceeded a limit, or carried ambiguous
	// framing. The default is to fail closed.
	//
	// Under Coraza this was never a decision anyone made: a processing error
	// fell through to the next handler, so the gateway failed open silently and
	// nothing recorded that it had. Making it a field means the choice is
	// stated, appears in the config fingerprint, and can differ by tier.
	// Configure with the "fail_open" key or GATEON_WAF_FAIL_OPEN.
	FailOpen bool
	// ExtraRules are typed rules supplied programmatically, replacing the
	// SecLang "Directives" string. A rule is now a value that either compiles
	// or does not, rather than text concatenated into a directive block where a
	// typo produced a rule that silently never fired.
	ExtraRules rules.Set
	RouteID    string // Route identifier for metrics

	// Per-family switches. They used to choose which OWASP CRS files to load;
	// they now select over gateon's own corpus by category and tag, which says
	// what a rule detects rather than which file it was filed in.
	DisableSQLI               bool
	DisableXSS                bool
	DisableLFI                bool
	DisableRCE                bool
	DisablePHP                bool
	DisableScanner            bool
	DisableProtocol           bool
	DisableJava               bool
	DisableNodeJS             bool
	DisableWordPress          bool
	EnableIPReputation        bool
	EnableDOSProtection       bool
	EnableMalwareDetection    bool
	EnableRansomwareDetection bool
	EnableDLP                 bool
	// EnableResponseInspection turns on the CRS RESPONSE-phase (data-leakage /
	// DLP) rules. These require buffering response bodies, which is the most
	// expensive part of the WAF in CPU, latency and memory, so it is off outside
	// the enterprise tier. When false, no RESPONSE-* rules are loaded and response
	// body access stays off.
	EnableResponseInspection    bool
	AnomalyThreshold            int
	EntropyThreshold            float64 // Threshold for Shannon entropy check (default 5.8)
	DisableEntropy              bool    // If true, skip fast-path entropy check
	EnableBodyEntropy           bool    // Enable entropy check on request body
	EnableFingerprintValidation bool    // Enable JA4+ fingerprint consistency check
	EnableConfidenceScoring     bool    // Enable confidence score calculation
	RequestBodyLimit            int     // Maximum request body size in bytes
	ResponseBodyLimit           int     // Maximum response body size in bytes
	AuditLogPath                string  // Path to audit log file
	AuditLogRelevantOnly        bool    // Only log relevant transactions
	EbpfManager                 ebpf.Manager
	Reputation                  *reputation.IPReputationStore
	AllowedAdminIps             []string // IPs allowed to access WP admin
	WafRules                    *waf.Store

	// AppProfiles names the platforms behind this route — "wordpress",
	// "drupal", "laravel", "issue_tracker" — each loading the scoped exceptions
	// that platform needs so it does not block on its own ordinary traffic.
	// Configure with the "app_profiles" key (comma-separated) or the
	// app_profiles field on the global WAF config.
	AppProfiles []string

	// EnableSSRFProtection blocks an off-origin URL in a parameter the server
	// fetches. Off by default: registering a webhook or importing an avatar is
	// the same request shape, so only a deployment that knows it never fetches
	// user-supplied URLs can say this is always an attack.
	EnableSSRFProtection bool

	// Origins are the hostnames this gateway serves, used to tell a destination
	// on this site from one somewhere else. They come from the routing table's
	// Host() rules and the operator's explicit list — never from the request,
	// which is the bug gwaf v0.4.1 fixed. Empty means the off-origin redirect
	// and SSRF rules have nothing to compare against and stay quiet.
	Origins []string
}

// Fingerprint returns a unique hash representing the WAF policy configuration.
// RouteID is excluded as it is a metadata field that differs between global
// and route-specific instances even when the security policy is identical.
func (c WAFConfig) Fingerprint() string {
	h := sha256.New()
	// Boolean and integer fields
	fmt.Fprintf(h, "b:%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v\n",
		c.TrustCloudflare, c.AuditOnly, c.DisableSQLI, c.DisableXSS,
		c.DisableLFI, c.DisableRCE, c.DisablePHP, c.DisableScanner, c.DisableProtocol,
		c.DisableJava, c.DisableNodeJS, c.DisableWordPress, c.EnableIPReputation,
		c.EnableDOSProtection, c.EnableMalwareDetection, c.EnableRansomwareDetection,
		c.EnableDLP, c.EnableResponseInspection, c.DisableEntropy, c.EnableBodyEntropy,
		c.EnableFingerprintValidation, c.EnableConfidenceScoring)
	fmt.Fprintf(h, "i:%d%d%d%d%d%t\n",
		c.ParanoiaLevel, c.AnomalyThreshold, c.RequestBodyLimit,
		c.ResponseBodyLimit, int(c.EntropyThreshold*100), c.FailOpen)
	// String fields
	fmt.Fprintf(h, "s:%s\n", c.AuditLogPath)
	// Programmatic rules are part of the policy, so two configs differing only
	// in them must not share a cached engine.
	for i := range c.ExtraRules {
		fmt.Fprintf(h, "r:%d|%s\n", c.ExtraRules[i].ID, c.ExtraRules[i].Msg)
	}

	// Slices
	if len(c.AllowedAdminIps) > 0 {
		fmt.Fprintf(h, "a:%s\n", strings.Join(c.AllowedAdminIps, ","))
	}
	// Platform profiles change which exceptions load and the SSRF opt-in changes
	// which rules do, so two configs differing only in these describe different
	// engines and must not share a cached one. Both are written unconditionally:
	// an empty profile list is a meaningful value, not an absent one.
	fmt.Fprintf(h, "p:%s|%t\n", waf.AppProfileFingerprint(c.AppProfiles), c.EnableSSRFProtection)
	// Origins decide what counts as off-origin, so two configs with different
	// ones reach different verdicts on the same request and must not share an
	// engine. Sorted, because the routing table's iteration order is not
	// meaningful and reordering it should not rebuild every engine.
	if len(c.Origins) > 0 {
		origins := slices.Clone(c.Origins)
		slices.Sort(origins)
		fmt.Fprintf(h, "o:%s\n", strings.Join(origins, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// grpcCompatDirective makes the OWASP CRS Protocol-Enforcement rules compatible
// with the gRPC / gRPC-Web transport. It MUST be loaded after
// REQUEST-901-INITIALIZATION (which seeds the defaults it overrides) and before
// REQUEST-920-PROTOCOL-ENFORCEMENT (whose rules read those values / are removed
// here). All directives are phase:1 and run in load order, so they take effect
// before 920 evaluates and before phase:2 body processing. Ids sit in the
// reserved range (99xxx) and do not collide with the CRS setup actions.
//
// Two gRPC incompatibilities are addressed:
//  1. 920420 ("content type not allowed"): gRPC content types are absent from the
//     CRS default tx.allowed_request_content_type list, so every gRPC request
//     scores a critical hit. We extend the default list with the gRPC family.
//     Values must be lowercase (920420 applies t:lowercase before @within).
//  2. 920180 ("POST without Content-Length or Transfer-Encoding"): gRPC runs over
//     HTTP/2, which carries neither header, so this rule fires on every gRPC
//     request. We remove it for gRPC content types only.
//
// We also turn request body access Off for gRPC: the body is binary protobuf that
// CRS cannot parse (it would only yield false positives on the SQLi/XSS/RCE body
// rules) and buffering it would break gRPC streaming. CRS still inspects the
// (text) gRPC request headers and URI, preserving real attack coverage.

var (
	reputationStrings [101]string
	wafInstanceCache  sync.Map // map[string]*gwaf.WAF

	safeHeaders = map[string]bool{
		"Authorization":        true,
		"Cookie":               true,
		"Set-Cookie":           true,
		"X-Csrf-Token":         true,
		"X-Xsrf-Token":         true,
		"Sec-Websocket-Key":    true,
		"Sec-Websocket-Accept": true,
		"X-Api-Key":            true,
		"X-API-Key":            true,
		"X-Auth-Token":         true,
		"X-Gateon-Fingerprint": true,
		"X-Request-Id":         true,
		"X-Correlation-Id":     true,
		"X-Amz-Date":           true,
		"X-Amz-Security-Token": true,
		"Content-Type":         true,
		"Accept-Encoding":      true,
		"User-Agent":           true,
		"Referer":              true,
		"Host":                 true,
		"Origin":               true,
		"Connection":           true,
		"Upgrade":              true,
		"Accept":               true,
		"Accept-Language":      true,
		"Cache-Control":        true,
		"Pragma":               true,
		"DNT":                  true,
	}
)

func init() {
	for i := 0; i <= 100; i++ {
		reputationStrings[i] = strconv.Itoa(i)
	}
}

// getReputationString returns a cached string for reputation scores 0-100.
func getReputationString(score float64) string {
	s := int(score)
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return reputationStrings[s]
}

// WAF returns a middleware that inspects requests with gwaf.
func WAF(cfg WAFConfig) (Middleware, error) {
	// The decision hook is set per engine rather than per request: it closes
	// over nothing request-specific, and the observation the recorder needs is
	// assembled at the call site where the request is still in scope.
	engine, err := newWAFEngine(cfg, nil)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Deduplication: Avoid double-checking if an identical WAF setup has already run.
			rs := request.GetRequestState(r)
			if rs != nil {
				if rs.IsManagement {
					next.ServeHTTP(w, r)
					return
				}
				fp := cfg.Fingerprint()
				for _, executed := range rs.ExecutedWAFs {
					if executed == fp {
						next.ServeHTTP(w, r)
						return
					}
				}
				rs.ExecutedWAFs = append(rs.ExecutedWAFs, fp)
				rs.ExecutedXSS = true
			}

			// 2. Ensure Host header is correctly set for Coraza and downstream services.
			if r.Host == "" && r.Header.Get("Host") != "" {
				r.Host = r.Header.Get("Host")
			}
			if r.Host != "" {
				r.Header["Host"] = []string{r.Host}
			}

			// Security Header Spoofing Prevention
			h := r.Header
			h.Del("X-Gateon-Reputation")
			testRep := h.Get("X-Gateon-Test-Reputation")
			h.Del("X-Gateon-Test-Reputation")
			h.Del("X-Gateon-Anomaly-Score")
			h.Del("X-Gateon-Threat-Type")
			h.Del("X-Gateon-WAF-Matched")
			h.Del("X-Gateon-JA4")

			// 3. CORS Preflight bypass
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Protocol enforcement, ahead of everything else: a request with
			// conflicting framing should not be inspected and forwarded, it
			// should be refused, and doing it first keeps the cost off the
			// path for conforming traffic.
			if !cfg.DisableProtocolChecks {
				if v := checkProtocol(r, cfg.AllowedMethods); v != nil {
					recordFastPathThreat(r, cfg.RouteID, "protocol_violation", v.reason)
					if !cfg.AuditOnly {
						http.Error(w, "Forbidden by Security Policy ("+v.reason+")", v.status)
						return
					}
				}
			}

			// 4. Cloudflare IP trust
			if cfg.TrustCloudflare {
				clientIP := request.GetClientIP(r, true)
				if last := strings.LastIndexByte(r.RemoteAddr, ':'); last != -1 && !strings.HasSuffix(r.RemoteAddr, "]") {
					r.RemoteAddr = clientIP + r.RemoteAddr[last:]
				} else {
					r.RemoteAddr = clientIP
				}
			}

			// 5. Adaptive WAF reputation scoring
			repScore := 100.0
			if rs != nil {
				repScore = rs.Reputation
			}

			if testRep != "" {
				if f, err := strconv.ParseFloat(testRep, 64); err == nil {
					repScore = f
				}
			}
			r.Header.Set("X-Gateon-Reputation", getReputationString(repScore))
			r.Header.Set("X-Gateon-JA4", telemetry.GetCachedJA4H(r))

			if repScore > 90 && isGitTraffic(r) {
				next.ServeHTTP(w, r)
				return
			}

			// The Aho-Corasick signature prefilter that used to run here was
			// retired. It blocked on a substring hit before the engine ran,
			// which made every literal a standalone rule with no grammar behind
			// it: bare SQL keywords refused "delete my account", WordPress paths
			// broke WordPress, and everything it caught with security value the
			// gwaf engine already catches by intent — in the URI and in the
			// headers alike. Keeping it was a fast path that *skipped* the
			// accurate check rather than cheapening it. The entropy,
			// fingerprint, and token checks below stay: those are gateon-owned
			// signals the stateless engine cannot produce.

			// Check entropy of common fields to detect shellcode/obfuscation
			if !cfg.DisableEntropy {
				if detail, found := suspiciousHeaderEntropy(r, cfg, repScore); found {
					recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", detail)
					http.Error(w, "Forbidden by Security Fast-Path (High Entropy Detected)", http.StatusForbidden)
					return
				}
			}

			// 1. Fingerprint Consistency Check (Spoofing Prevention)
			if cfg.EnableFingerprintValidation {
				ua := r.Header.Get("User-Agent")
				if isBrowserUA(ua) {
					// TLS Check
					if r.TLS != nil && isSuspiciousTLS(r) {
						details := fmt.Sprintf("Fingerprint mismatch: Browser UA '%s' with suspicious TLS profile (v%x)", ua, r.TLS.Version)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_fingerprint", details)
						http.Error(w, "Forbidden by Security (Client Spoofing Detected)", http.StatusForbidden)
						return
					}

					// H2/H3 Consistency Check
					if (r.ProtoMajor == 2 || r.ProtoMajor == 3) && r.Header.Get("Connection") != "" {
						// Connection header is forbidden in HTTP/2 and HTTP/3
						details := fmt.Sprintf("Protocol violation: %s request from '%s' contains forbidden 'Connection' header", r.Proto, ua)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_protocol_violation", details)
						http.Error(w, "Forbidden by Security (Protocol Violation)", http.StatusForbidden)
						return
					}

					// Modern browsers always send certain headers
					if r.ProtoMajor >= 2 && r.Header.Get("Accept-Encoding") == "" {
						details := fmt.Sprintf("Suspicious client: %s request from '%s' missing 'Accept-Encoding'", r.Proto, ua)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_suspicious_client", details)
						http.Error(w, "Forbidden by Security (Suspicious Client)", http.StatusForbidden)
						return
					}
				}
			}

			// 2. Body Entropy Check (Fast-Path)
			if cfg.EnableBodyEntropy && r.ContentLength > 0 && r.ContentLength < maxBodyEntropyScan {
				if detail, found := suspiciousBodyEntropy(r, rs, cfg, repScore); found {
					recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", detail)
					http.Error(w, "Forbidden by Security Fast-Path (High Body Entropy Detected)", http.StatusForbidden)
					return
				}
			}

			// 3. Security Token Fast-Check
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token := auth[7:]
				// We enforce structure only for tokens that claim to be a known format (JWT, Paseto).
				if len(token) > 32 && strings.Contains(token, ".") {
					isMalformed := false
					if isLikelyJWT(token) {
						if !isJWT(token) {
							isMalformed = true
						}
					} else if isLikelyPaseto(token) {
						if !isPaseto(token) {
							isMalformed = true
						}
					}

					if isMalformed {
						recordFastPathThreat(r, cfg.RouteID, "fast_path_malformed_token", "Malformed security token structure in Authorization header")
						http.Error(w, "Forbidden by Security (Malformed Security Token)", http.StatusForbidden)
						return
					}
				}
			}

			// Deterministic Trace Correlation
			traceID := telemetry.GetCachedJA4H(r) // Use JA4H as a deterministic trace correlation component if OTel is missing
			r.Header.Set("X-Gateon-Fingerprint", traceID)

			// Global IP Reputation check
			if cfg.EnableIPReputation && cfg.Reputation != nil {
				clientIP := request.GetClientIP(r, cfg.TrustCloudflare)
				if bad, score := cfg.Reputation.IsBad(clientIP); bad {
					r.Header.Set("X-Gateon-IP-Reputation-Score", strconv.FormatFloat(score, 'f', 2, 64))
					if score >= cfg.Reputation.GetBlockThreshold() {
						r.Header.Set("X-Gateon-IP-Reputation-Block", "1")
					}
				}
			}

			tx, decision, err := engine.inspectRequest(r, repScore)
			// inspectRequest returns a live transaction on every path, error
			// included, so the audit trail survives a failed inspection. Guard
			// the nil case anyway: this defer runs on the request path, and a
			// future early return here would otherwise panic on every request
			// rather than honour cfg.FailOpen below.
			if tx != nil {
				defer tx.Close()
			}

			observe := func(d gwaf.Decision) {
				matches := tx.Matches()
				obs := wafObservation{
					decision: d, matches: matches, request: r,
					routeID: cfg.RouteID, cfg: cfg, repScore: repScore,
				}
				recordWAFDecision(obs)
				engine.audit.record(d, matches, obs)
			}

			if err != nil {
				// The engine could not finish inspecting. Whether that permits
				// the request is a policy decision, not an accident of control
				// flow: under Coraza this path fell through to the next handler
				// and the gateway failed open with nothing recording that it
				// had.
				logger.L.LogError("WAF could not inspect the request",
					"error", err, "route", cfg.RouteID, "fail_open", cfg.FailOpen)
				if !cfg.FailOpen {
					http.Error(w, "Forbidden by Security Policy (request could not be inspected)",
						http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			if decision != nil {
				observe(*decision)
				if !cfg.AuditOnly {
					status := decision.Status()
					if status == 0 {
						status = http.StatusForbidden
					}
					http.Error(w, "Forbidden by Security Policy (WAF)", status)
					return
				}
			} else {
				observe(tx.Decision())
			}

			if !cfg.EnableResponseInspection {
				next.ServeHTTP(w, r)
				return
			}

			// Response inspection. The response is streamed through the engine
			// rather than buffered: the previous implementation accumulated the
			// entire upstream response in memory before writing any of it, which
			// is an unbounded allocation keyed on upstream behaviour and breaks
			// server-sent events and any long-lived stream.
			//
			// The cost of streaming is that headers are committed before the body
			// is seen, so a response-body match can no longer change the status
			// code. It truncates the response instead, which is the honest
			// trade: the leaked bytes stop either way, and a client that received
			// a 200 with a truncated body is strictly better off than one that
			// waited for the whole thing to be buffered.
			ww := &wafResponseWriter{
				ResponseWriter: w,
				tx:             tx,
				auditOnly:      cfg.AuditOnly,
				onDecision:     observe,
				bufLimit:       responseBufferLimit(cfg),
			}
			next.ServeHTTP(ww, r)
			ww.finish()
		})
		return h
	}, nil
}

func recordFastPathThreat(r *http.Request, routeID, typeStr, details string) {
	clientIP := request.GetClientIP(r, true)
	category := "general"
	lowerDetails := strings.ToLower(details)
	recommendation := "Review your request for suspicious patterns. If this is legitimate traffic, consider adjusting the Fast-Path sensitivity."

	if strings.Contains(lowerDetails, "sql") || strings.Contains(lowerDetails, "union") {
		category = "sqli"
		recommendation = "SQL patterns were detected in the request. Ensure you are not sending raw SQL fragments in your headers or parameters."
	} else if strings.Contains(lowerDetails, "script") || strings.Contains(lowerDetails, "xss") {
		category = "xss"
		recommendation = "Script-like patterns were detected. Avoid using <script> tags or common XSS vectors in headers like Referer or User-Agent."
	} else if strings.Contains(lowerDetails, "scanner") || strings.Contains(lowerDetails, "nmap") || strings.Contains(lowerDetails, "sqlmap") {
		category = "bot"
		recommendation = "Your request was flagged as a known automated scanner or bot. If you are a developer, ensure your tool uses a legitimate User-Agent."
	}

	// Record in OpenTelemetry span
	if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
		span.SetAttributes(
			attribute.Bool("security.blocked", true),
			attribute.String("security.threat_type", typeStr),
			attribute.String("security.details", details),
			attribute.String("security.category", category),
			attribute.String("security.recommendation", recommendation),
		)
		span.SetStatus(codes.Error, "Blocked by Security Fast-Path: "+typeStr)
	}

	if rs := request.GetRequestState(r); rs != nil {
		rs.Recommendation = recommendation
	}
	telemetry.RegisterRecommendation(GetRequestID(r), recommendation)

	rules := ""
	switch typeStr {
	case "fast_path_signature":
		rules = "[1900001]"
	case "fast_path_entropy":
		rules = "[1900002]"
	case "fast_path_fingerprint":
		rules = "[1900003]"
	case "fast_path_protocol_violation":
		rules = "[1900004]"
	case "fast_path_suspicious_client":
		rules = "[1900005]"
	case "fast_path_malformed_token":
		rules = "[1990002]"
	}

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:           typeStr,
		SourceIP:       clientIP,
		Fingerprint:    telemetry.GetJA4Plus(r),
		Score:          100,
		Details:        details,
		TriggeredRules: rules,
		Recommendation: recommendation,
		Time:           time.Now(),
		RouteID:        routeID,
		RequestURI:     r.RequestURI,
		UserAgent:      r.UserAgent(),
		Method:         r.Method,
		Category:       category,
		Severity:       "critical",
		ActionTaken:    "blocked",
		Mitigated:      true,
	}))
}

func isSafeHeader(name string) bool {
	// Fast path for canonical headers
	if safeHeaders[name] {
		return true
	}

	// Prefix checks without allocation
	if hasPrefixFold(name, "X-Amz-") ||
		hasPrefixFold(name, "X-Goog-") ||
		hasPrefixFold(name, "X-Apple-") ||
		hasPrefixFold(name, "X-Ms-") ||
		hasPrefixFold(name, "Grpc-") ||
		hasPrefixFold(name, "Access-Control-") ||
		hasPrefixFold(name, "Sec-Ch-") {
		return true
	}

	// Fallback for non-canonical forms or mixed case
	return safeHeaders[strings.ToLower(name)]
}

func calculateConfidence(reputation float64, severity string, anomalyScore int, isFastPath bool) float64 {
	base := 0.5
	if isFastPath {
		base = 0.9 // Deterministic matches are high confidence
	} else {
		// Severity impact
		switch severity {
		case "critical":
			base += 0.3
		case "high":
			base += 0.2
		case "medium":
			base += 0.1
		}

		// Anomaly score impact (Threshold is usually 5)
		if anomalyScore >= 20 {
			base += 0.2
		} else if anomalyScore >= 10 {
			base += 0.1
		}
	}

	// Reputation impact: High reputation reduces confidence of it being a real threat (Likely FP)
	// Reputation 100 -> -0.4 impact
	// Reputation 0 -> +0.1 impact
	repImpact := (50.0 - reputation) / 100.0 * 0.5
	confidence := base + repImpact

	return min(max(confidence, 0.1), 0.99)
}

func isGitTraffic(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "application/x-git-receive-pack-request" || ct == "application/x-git-upload-pack-request" {
		return true
	}
	path := r.URL.Path
	return strings.HasSuffix(path, "/git-receive-pack") || strings.HasSuffix(path, "/git-upload-pack")
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// parseWAFConfig turns the middleware's string configuration into a typed one.
func parseWAFConfig(cfg map[string]string) WAFConfig {
	pl := 1
	if v := cfg["paranoia_level"]; v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= 4 {
			pl = n
		}
	}
	auditOnly := strings.TrimSpace(strings.ToLower(cfg["audit_only"])) == "true" ||
		strings.TrimSpace(strings.ToLower(cfg["audit_only"])) == "1"

	isFalse := func(key string) bool {
		v, ok := cfg[key]
		if !ok {
			return false
		}
		return strings.TrimSpace(strings.ToLower(v)) == "false"
	}

	routeID := cmp.Or(cfg["route"], cfg["route_id"])
	if routeID == "" {
		routeID = "unknown"
	}

	var allowedAdminIps []string
	if v, ok := cfg["allowed_admin_ips"]; ok && v != "" {
		for _, s := range strings.Split(v, ",") {
			if ip := strings.TrimSpace(s); ip != "" {
				allowedAdminIps = append(allowedAdminIps, ip)
			}
		}
	}

	anomalyThreshold := intVal(cfg["anomaly_threshold"])
	entropyThreshold := 5.8
	if v, ok := cfg["entropy_threshold"]; ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			entropyThreshold = f
		}
	}
	disableEntropy := strings.TrimSpace(strings.ToLower(cfg["disable_entropy"])) == "true" ||
		strings.TrimSpace(strings.ToLower(cfg["disable_entropy"])) == "1"

	// Availability over inspection is a deliberate choice, so it is only true
	// when someone wrote it down. An unset key means fail closed.
	failOpen := strings.TrimSpace(strings.ToLower(cfg["fail_open"])) == "true" ||
		strings.TrimSpace(strings.ToLower(cfg["fail_open"])) == "1"

	return WAFConfig{
		ParanoiaLevel:               pl,
		TrustCloudflare:             request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
		AuditOnly:                   auditOnly,
		DisableSQLI:                 isFalse("sqli"),
		DisableXSS:                  isFalse("xss"),
		DisableLFI:                  isFalse("lfi"),
		DisableRCE:                  isFalse("rce"),
		DisablePHP:                  isFalse("php"),
		DisableScanner:              isFalse("scanner"),
		DisableProtocol:             isFalse("protocol"),
		DisableJava:                 isFalse("java"),
		DisableNodeJS:               isFalse("nodejs"),
		DisableWordPress:            isFalse("wordpress"),
		EnableIPReputation:          strings.TrimSpace(strings.ToLower(cfg["ip_reputation"])) == "true",
		EnableDOSProtection:         strings.TrimSpace(strings.ToLower(cfg["dos_protection"])) == "true",
		EnableMalwareDetection:      strings.TrimSpace(strings.ToLower(cfg["malware_detection"])) == "true",
		EnableRansomwareDetection:   strings.TrimSpace(strings.ToLower(cfg["ransomware_detection"])) == "true",
		EnableDLP:                   strings.TrimSpace(strings.ToLower(cfg["dlp"])) == "true",
		EnableBodyEntropy:           strings.TrimSpace(strings.ToLower(cfg["enable_body_entropy"])) == "true",
		EnableFingerprintValidation: strings.TrimSpace(strings.ToLower(cfg["enable_fingerprint_validation"])) == "true",
		EnableConfidenceScoring:     strings.TrimSpace(strings.ToLower(cfg["enable_confidence_scoring"])) != "false", // Default true
		AnomalyThreshold:            anomalyThreshold,
		EntropyThreshold:            entropyThreshold,
		DisableEntropy:              disableEntropy,
		FailOpen:                    failOpen,
		AllowedMethods:              parseAllowedMethods(cfg["allowed_methods"]),
		DisableProtocolChecks:       isFalse("protocol"),
		RequestBodyLimit:            intVal(cfg["request_body_limit"]),
		ResponseBodyLimit:           intVal(cfg["response_body_limit"]),
		AuditLogPath:                strings.TrimSpace(cfg["audit_log_path"]),
		AuditLogRelevantOnly:        strings.TrimSpace(strings.ToLower(cfg["audit_log_relevant_only"])) != "false",
		RouteID:                     routeID,
		AllowedAdminIps:             allowedAdminIps,
		AppProfiles:                 parseAppProfiles(cfg["app_profiles"]),
		EnableSSRFProtection:        strings.TrimSpace(strings.ToLower(cfg["ssrf_protection"])) == "true",
		Origins:                     resolveOrigins(parseCSV(cfg["origins"])),
	}
}

// parseAppProfiles reads the comma-separated platform list.
//
// Validation is deliberately not done here. An unrecognised name has to survive
// as far as the engine build, which is the one place that knows the profile set
// of the linked engine and can log it against a route; dropping it here would
// turn a typo into silence.
func parseAppProfiles(v string) []string { return parseCSV(v) }

// parseCSV splits a comma-separated config value, dropping empty entries.
func parseCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intVal(v string) int {
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

// peekBody reads up to n bytes from the request body and restores it.
// It is used for fast-path inspection without consuming the body for downstream.
func peekBody(r *http.Request, n int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	peeked, err := io.ReadAll(io.LimitReader(r.Body, n))
	if err != nil {
		return nil, err
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
		Closer: r.Body,
	}
	return peeked, nil
}

func isBrowserUA(ua string) bool {
	return strings.Contains(ua, "Mozilla/5.0")
}

func isSuspiciousTLS(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}
	// Modern browsers use TLS 1.2 or 1.3
	if r.TLS.Version < 0x0303 { // < TLS 1.2
		return true
	}

	// Browser consistency check:
	// Most modern browsers support a large number of cipher suites,
	// but automated tools often use a very limited or old set.
	ua := r.Header.Get("User-Agent")
	if isBrowserUA(ua) {
		// If UA claims to be a modern browser but only supports few/old ciphers, it's suspicious.
		negotiated := r.TLS.CipherSuite
		// Some very old/weak ciphers that modern browsers would never negotiate if anything else is available:
		switch negotiated {
		case 0x0005, 0x0004, 0x000a: // RSA_WITH_RC4_128_SHA, RSA_WITH_RC4_128_MD5, RSA_WITH_3DES_EDE_CBC_SHA
			return true
		}
	}
	return false
}

// isJWT checks if a token has a valid 3-part base64url structure.
func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !isBase64URL(p) {
			return false
		}
	}
	return true
}

// isLikelyJWT reports whether the token starts with common JWT header prefixes.
func isLikelyJWT(token string) bool {
	// JWT headers are JSON objects. Base64url of '{"' is 'eyJ'.
	return strings.HasPrefix(token, "eyJ")
}

// isLikelyPaseto reports whether the token starts with a Paseto version prefix.
func isLikelyPaseto(token string) bool {
	return len(token) > 9 && (strings.HasPrefix(token, "v1.") || strings.HasPrefix(token, "v2.") ||
		strings.HasPrefix(token, "v3.") || strings.HasPrefix(token, "v4."))
}

// isPaseto checks if a token has a valid Paseto structure (3 or 4 parts).
func isPaseto(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	// Paseto uses a version (v1-v4) and purpose (local/public) header.
	if !strings.HasPrefix(parts[0], "v") || len(parts[0]) != 2 {
		return false
	}
	if parts[1] != "local" && parts[1] != "public" {
		return false
	}
	for _, p := range parts {
		if !isBase64URL(p) {
			return false
		}
	}
	return true
}

// isBase64URL checks if a string is a valid base64url encoded string.
func isBase64URL(s string) bool {
	if s == "" {
		return true // Allow empty parts
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// wafResponseWriter runs the response phases over the upstream response.
//
// Response-body inspection has to buffer, and this is the one place in the WAF
// where that is true. Bytes already written to the client cannot be recalled,
// so a data-leak rule that inspected a streamed response could only report the
// leak after it had happened — which is not what a DLP control is for. The
// previous implementation buffered the *entire* response, an allocation bounded
// only by upstream behaviour; this one buffers to an explicit ceiling.
//
// Past the ceiling the buffer is flushed and the remainder streams through
// uninspected. That is a real limit and it is stated rather than hidden: the
// alternative is either an unbounded buffer or refusing large responses
// outright, and inspecting the first N bytes is what every response-inspecting
// proxy actually does.
//
// Header-phase rules do not need any of this, so a config with response
// inspection enabled but no body rules never buffers at all.
type wafResponseWriter struct {
	http.ResponseWriter
	tx            *gwaf.Transaction
	status        int
	blocked       bool
	headerWritten bool
	flushed       bool
	auditOnly     bool
	onDecision    func(gwaf.Decision)

	buf      bytes.Buffer
	bufLimit int
}

// WriteHeader runs the response-headers phase and holds the status back while
// the body is being buffered, so a body rule can still change it.
func (w *wafResponseWriter) WriteHeader(status int) {
	if w.blocked || w.headerWritten {
		return
	}
	w.headerWritten = true
	w.status = status

	w.tx.SetResponseStatus(status)
	for name, values := range w.Header() {
		for _, v := range values {
			w.tx.AddResponseHeader(name, v)
		}
	}
	if d := w.tx.ProcessResponseHeaders(); d.Blocked() && !w.auditOnly {
		w.block(d)
		return
	}
	if w.bufLimit <= 0 {
		w.commitHeader()
	}
}

func (w *wafResponseWriter) Write(b []byte) (int, error) {
	if w.blocked {
		// The response is refused. Reporting the write as accepted keeps the
		// upstream handler from logging an error about a client that is not
		// the reason the write went nowhere.
		return len(b), nil
	}
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
		if w.blocked {
			return len(b), nil
		}
	}

	if d := w.tx.WriteResponseBody(b); d.Blocked() && !w.auditOnly {
		w.block(d)
		return len(b), nil
	}

	if w.bufLimit > 0 && !w.flushed {
		if w.buf.Len()+len(b) <= w.bufLimit {
			w.buf.Write(b)
			return len(b), nil
		}
		// The ceiling is reached: everything from here on is uninspectable, so
		// commit what is held and stop buffering.
		if err := w.flush(); err != nil {
			return 0, err
		}
	}
	return w.ResponseWriter.Write(b)
}

// finish runs the response-body phase and releases whatever is still buffered.
// It must be called once the upstream handler has returned.
func (w *wafResponseWriter) finish() {
	if w.blocked {
		return
	}
	if d := w.tx.ProcessResponseBody(); d.Blocked() && !w.auditOnly {
		w.block(d)
		return
	}
	_ = w.flush()
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
		_ = w.flush()
	}
}

// flush commits the held status and buffered bytes.
func (w *wafResponseWriter) flush() error {
	if w.flushed {
		return nil
	}
	w.flushed = true
	w.commitHeader()
	if w.buf.Len() == 0 {
		return nil
	}
	// #nosec G705 -- these are the origin's own response bytes being forwarded
	// by a reverse proxy, along with the origin's Content-Type. Gateon is not
	// the author of this body and does not interpolate into it.
	_, err := w.ResponseWriter.Write(w.buf.Bytes())
	w.buf.Reset()
	return err
}

func (w *wafResponseWriter) commitHeader() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.ResponseWriter.WriteHeader(w.status)
}

// block refuses the response.
func (w *wafResponseWriter) block(d gwaf.Decision) {
	w.blocked = true
	w.buf.Reset()
	if w.onDecision != nil {
		w.onDecision(d)
	}
	if w.flushed {
		// Headers are already on the wire, so the status cannot be changed.
		// Sending nothing further is all that is left, and it still stops the
		// remainder of the leak.
		return
	}
	w.flushed = true
	status := d.Status()
	if status == 0 {
		status = http.StatusForbidden
	}
	w.ResponseWriter.WriteHeader(status)
	_, _ = w.ResponseWriter.Write([]byte("Forbidden by Security Policy (response blocked)"))
}

func (w *wafResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// Flush forwards to the underlying writer once buffering is done, so streaming
// responses keep working. While the body is still being buffered for
// inspection there is deliberately nothing to flush.
func (w *wafResponseWriter) Flush() {
	if w.blocked {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok && w.flushed {
		f.Flush()
	}
}

func (w *wafResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func splitAddr(addr string) (string, int) {
	if last := strings.LastIndexByte(addr, ':'); last != -1 {
		port, _ := strconv.Atoi(addr[last+1:])
		host := addr[:last]
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		return host, port
	}
	return addr, 0
}

// defaultResponseBufferLimit bounds response-body inspection when the config
// names no limit of its own. One mebibyte holds an API response or an HTML page
// whole, which is where leaked credentials and card numbers actually appear,
// without letting a large download sit in memory.
const defaultResponseBufferLimit = 1 << 20

// responseBufferLimit reports how many response bytes may be held for
// inspection. Zero means the response is not buffered at all.
func responseBufferLimit(cfg WAFConfig) int {
	if !cfg.EnableResponseInspection {
		return 0
	}
	if cfg.ResponseBodyLimit > 0 {
		return cfg.ResponseBodyLimit
	}
	return defaultResponseBufferLimit
}

// Entropy fast-path.
//
// A high Shannon entropy value in a place that normally holds text is a cheap
// proxy for packed shellcode or an obfuscated payload, and it costs one pass
// over the bytes. The threshold moves with reputation because the same value
// means different things from a client with history and one without.

const (
	// defaultEntropyThreshold is the bits-per-byte above which a text field is
	// treated as suspicious. Ordinary text sits well below it; compressed or
	// encrypted data sits near 8.
	defaultEntropyThreshold = 5.8

	// minEntropySample is the shortest value worth scoring. Shannon entropy on
	// a handful of bytes is noise.
	minEntropySample = 64

	// maxBodyEntropyScan bounds the bodies considered at all, and
	// bodyEntropyPeek how much of one is read.
	maxBodyEntropyScan = 1024 * 1024
	bodyEntropyPeek    = 2048
)

// entropyThreshold applies the configured value and the reputation adjustment.
func entropyThreshold(cfg WAFConfig, reputation float64) float64 {
	threshold := cfg.EntropyThreshold
	if threshold <= 0 {
		threshold = defaultEntropyThreshold
	}
	switch {
	case reputation > 90:
		threshold += 0.5
	case reputation < 20:
		threshold -= 0.5
	}
	return threshold
}

// suspiciousHeaderEntropy reports the first header whose value scores above the
// threshold, along with the detail to record.
func suspiciousHeaderEntropy(r *http.Request, cfg WAFConfig, reputation float64) (string, bool) {
	threshold := entropyThreshold(cfg, reputation)
	for key, values := range r.Header {
		if isSafeHeader(key) {
			continue
		}
		for _, v := range values {
			if len(v) <= minEntropySample || !entropy.IsSuspicious(v, threshold) {
				continue
			}
			return fmt.Sprintf("High entropy in header %s: %.2f (threshold %.2f)",
				key, entropy.CalculateString(v), threshold), true
		}
	}
	return "", false
}

// suspiciousBodyEntropy scores the head of the request body.
func suspiciousBodyEntropy(r *http.Request, rs *request.RequestState, cfg WAFConfig, reputation float64) (string, bool) {
	peeked, err := peekBody(r, bodyEntropyPeek)
	if err != nil || len(peeked) <= minEntropySample {
		return "", false
	}
	if rs != nil {
		rs.ExecutedEntropy = true
	}

	threshold := entropyThreshold(cfg, reputation)
	// Structured payloads carry more punctuation and less repetition than prose,
	// so they score higher without being suspicious.
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "form") {
		threshold += 0.2
	}

	if !entropy.IsSuspiciousBytes(peeked, threshold) {
		return "", false
	}
	return fmt.Sprintf("High entropy in request body: %.2f (threshold %.2f)",
		entropy.Calculate(peeked), threshold), true
}
