package middleware

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/scanner"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// WAFConfig configures the WAF middleware.
type WAFConfig struct {
	UseCRS           bool   // Use OWASP CRS (default true)
	ParanoiaLevel    int    // CRS paranoia level 1-4 (default 1)
	DirectivesFile   string // Optional path to custom directives file
	TrustCloudflare  bool   // Use CF-Connecting-IP for REMOTE_ADDR in request
	AuditOnly        bool   // If true, log matches but do not block (SecRuleEngine DetectionOnly)
	GlobalDirectives string // Combined global rules from GlobalConfig
	Directives       string // Custom SecLang directives (replaces DirectivesFile)
	RouteID          string // Route identifier for metrics

	// Specific CRS protections (only used if UseCRS is true)
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
	RulesPath                   string   // Path to external WAF rules (CRS)
	WafRules                    *waf.Store

	// GRPCMode relaxes the CRS Protocol-Enforcement rules that are structurally
	// incompatible with the gRPC/HTTP-2 transport (see grpcCompatDirective) and
	// skips the binary-hostile fast-paths for gRPC requests. It MUST be derived
	// from the trusted server-side route type (rt.Type == "grpc"), never from a
	// client-supplied header: a single shared WAF instance protects every route,
	// so gating on the request Content-Type would let an attacker disable body
	// inspection on a plain HTTP route by spoofing "Content-Type: application/grpc".
	GRPCMode bool
}

// Fingerprint returns a unique hash representing the WAF policy configuration.
// RouteID is excluded as it is a metadata field that differs between global
// and route-specific instances even when the security policy is identical.
func (c WAFConfig) Fingerprint() string {
	h := sha256.New()
	// Boolean and integer fields
	fmt.Fprintf(h, "b:%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v\n",
		c.UseCRS, c.TrustCloudflare, c.AuditOnly, c.DisableSQLI, c.DisableXSS,
		c.DisableLFI, c.DisableRCE, c.DisablePHP, c.DisableScanner, c.DisableProtocol,
		c.DisableJava, c.DisableNodeJS, c.DisableWordPress, c.EnableIPReputation,
		c.EnableDOSProtection, c.EnableMalwareDetection, c.EnableRansomwareDetection,
		c.EnableDLP, c.EnableResponseInspection, c.DisableEntropy, c.EnableBodyEntropy,
		c.EnableFingerprintValidation, c.EnableConfidenceScoring)
	fmt.Fprintf(h, "i:%d%d%d%d%d%t\n",
		c.ParanoiaLevel, c.AnomalyThreshold, c.RequestBodyLimit,
		c.ResponseBodyLimit, int(c.EntropyThreshold*100), c.GRPCMode)
	// String fields
	fmt.Fprintf(h, "s:%s|%s|%s|%s|%s\n",
		c.DirectivesFile, c.GlobalDirectives, c.Directives, c.AuditLogPath, c.RulesPath)
	// Slices
	if len(c.AllowedAdminIps) > 0 {
		fmt.Fprintf(h, "a:%s\n", strings.Join(c.AllowedAdminIps, ","))
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

// isGRPCRequest reports whether the request carries a gRPC or gRPC-Web payload.
// gRPC frames are binary protobuf with high Shannon entropy and binary "-bin"
// metadata headers; the deterministic byte/entropy fast-paths would false-positive
// on that framing, so they are skipped for gRPC traffic. The CRS engine still
// inspects gRPC request headers and the URI.
func isGRPCRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

var (
	reputationStrings [101]string
	wafInstanceCache  sync.Map // map[string]coraza.WAF
	hashPool          = sync.Pool{
		New: func() any {
			return sha256.New()
		},
	}
	fastScanner = scanner.NewScanner([]string{
		"SELECT ", "UNION ", "INSERT ", "DELETE ", "UPDATE ", "DROP ", "EXEC ", "sleep(", "benchmark(", "waitfor delay", // SQLi
		"<script", "javascript:", "onload=", "onerror=", "eval(", "atob(", "alert(", "confirm(", "prompt(", // XSS
		"/etc/passwd", "/etc/shadow", "/bin/sh", "cmd.exe", "/proc/self/", "/windows/system32", // LFI/RCE
		"<?php", "base64_decode", "shell_exec", "system(", "passthru(", "exec(", // PHP
		"authorized_keys", "id_rsa", "id_dsa", ".ssh/", // Creds
		"powershell", "curl http", "wget http", "python -c", "perl -e", "ruby -e", // RCE
		"nessustoken", "qualys-scan", "acunetix", "sqlmap", "nikto", "nmap", "masscan", // Scanners
		"zgrab", "gobuster", "dirb", "dirbuster", "ffuf", "hydra", "burp", "metasploit", // Scanners
		"w3af", "absenthe", "blackwidow", "commix", "darkstat", "dnsmap", "dnsrecon", // Scanners
		"runtime.exec", "java.lang.Runtime", "java.lang.ProcessBuilder", "javax.crypto", // Java
		"os/exec", "net/http/httputil", "reflect.ValueOf", "unsafe.Pointer", // Golang
		"wp-admin", "wp-login", "wp-config.php", "xmlrpc.php", "wp-json", // WordPress
		"wp-links-opml.php", "wp-config-sample.php", "readme.html", "license.txt", // WP info
		"log4j", "jndi:ldap", "jndi:rmi", "${jndi:", // Log4j
		"{{", "#{", "<%", "spring.datasource", "spring.cloud", // SSTI / Spring
		"fs.readFile", "child_process", "process.env", // NodeJS
		"metadata.google.internal", "169.254.169.254", // SSRF
	})

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

var crsRuleExplanations = map[int]struct {
	Explanation    string
	Recommendation string
}{
	911100: {
		Explanation:    "The HTTP method used (e.g., PUT, DELETE) is not allowed by your security policy for this path.",
		Recommendation: "Ensure you are using standard methods like GET or POST, or update the 'Allowed Methods' in Gateon settings.",
	},
	920170: {
		Explanation:    "The request is a GET or HEAD but includes a message body, which is technically non-standard and often blocked by security policies.",
		Recommendation: "Ensure your client is not sending a body with GET requests. If this is required by your API, use the 'Mark as False Positive' button to allow it for this path.",
	},
	920180: {
		Explanation:    "The request is missing a mandatory size header (Content-Length) for a POST operation.",
		Recommendation: "Ensure your client or proxy sends a proper Content-Length header for all POST/PUT requests.",
	},
	920420: {
		Explanation:    "The 'Content-Type' header value is not permitted by the security policy.",
		Recommendation: "Check if the application expects this specific content type. If legitimate, add it to the allowed list.",
	},
	932100: {
		Explanation:    "A system command execution pattern (RCE) was detected. The request looks like an attempt to run commands on the server.",
		Recommendation: "If this is a false positive, it might be due to shell-like characters in your input. Consider whitelisting this specific field.",
	},
	941010: {
		Explanation:    "The request path (URI) triggered a security filter for suspicious characters or restricted file extensions.",
		Recommendation: "This often happens with complex identifiers like UUIDs in the path. If the path is legitimate, use the 'Mark as False Positive' button.",
	},
	941100: {
		Explanation:    "A script injection pattern (XSS) was detected. The input contains characters that could be executed by a browser.",
		Recommendation: "Sanitize your input by removing HTML tags or use the 'Mark as False Positive' button if this is expected data.",
	},
	941110: {
		Explanation:    "A direct script tag (<script>) was detected. This is a very high-confidence indicator of a script injection attempt.",
		Recommendation: "Do not include raw HTML or script tags in request parameters unless absolutely necessary and encoded.",
	},
	942100: {
		Explanation:    "A database query pattern (SQLi) was detected. The request contains keywords like 'SELECT', 'DROP', or '--' that look like database commands.",
		Recommendation: "Avoid using SQL keywords or special characters like single quotes in your request data. For tokens/hashes, use the auto-fix button.",
	},
	942270: {
		Explanation:    "A classic SQL 'UNION' attack pattern was detected, commonly used to steal data from databases.",
		Recommendation: "Verify if the request data contains accidental SQL-like syntax. This is a high-risk violation.",
	},
	949110: {
		Explanation:    "This request was blocked because its total 'Anomaly Score' exceeded the threshold after triggering multiple security rules.",
		Recommendation: "Review the individual violations categorized below. For legitimate traffic, use the one-click resolution to whitelist the specific rules.",
	},
	100008: {
		Explanation:    "A common web shell filename (e.g., c99.php, shell.php) was detected in the request URI.",
		Recommendation: "This is a high-confidence indicator of a malware or compromise attempt. If this is a legitimate file, ensure it is properly registered.",
	},
	100009: {
		Explanation:    "A ransomware-related filename (e.g., README_FOR_DECRYPT.txt) was detected in the request URI.",
		Recommendation: "This strongly suggests a ransomware presence or scan. Investigate the client source immediately.",
	},
	110000: {
		Explanation:    "A known vulnerability scanner (e.g., Nikto, sqlmap, Acunetix) was detected based on its User-Agent or headers.",
		Recommendation: "Block this IP if it's not an authorized security scan. Automated tools are often the first step in an attack.",
	},
	120010: {
		Explanation:    "A 'Header Flood' (DDoS) attempt was detected. The request contains an excessive number of headers.",
		Recommendation: "This is likely a denial-of-service attempt. The IP has been automatically mitigated to protect service availability.",
	},
	130000: {
		Explanation:    "Sensitive data (Credit Card Number) was detected in the response body, triggering a Data Leakage Prevention (DLP) block.",
		Recommendation: "Ensure your application is not accidentally exposing sensitive customer data. Check the response logs to identify the source.",
	},
	130001: {
		Explanation:    "Sensitive data (US Social Security Number) was detected in the response body, triggering a DLP block.",
		Recommendation: "Exposure of PII like SSNs is a critical compliance violation. Audit the backend service for data leaks.",
	},
	130005: {
		Explanation:    "A Slack Webhook URL was detected in the response body, which could allow unauthorized message posting.",
		Recommendation: "Revoke the Slack Webhook immediately and ensure it is not hardcoded in the application response.",
	},
	130006: {
		Explanation:    "A GitHub Personal Access Token (PAT) was detected in the response body.",
		Recommendation: "Revoke the GitHub token immediately and check for accidental exposure in logs or API responses.",
	},
	130007: {
		Explanation:    "A Google OAuth Client Secret was detected in the response body.",
		Recommendation: "Rotate the OAuth Client Secret in the Google Cloud Console and audit the backend logic.",
	},
	140000: {
		Explanation:    "A time-based 'Blind SQL Injection' attempt was detected (e.g., using sleep() or waitfor delay).",
		Recommendation: "The attacker is trying to infer database content based on response delays. This is a highly sophisticated attack.",
	},
	100014: {
		Explanation:    "A 'Shellshock' (CVE-2014-6271) exploit attempt was detected in the request headers.",
		Recommendation: "Ensure your environment is patched against old RCE vulnerabilities. This is a classic automated exploit attempt.",
	},
}

func getRuleCategory(id int) string {
	switch {
	case id >= 911000 && id <= 911999:
		return "Access Policy"
	case id >= 920000 && id <= 920999:
		return "Protocol Compliance"
	case id >= 921000 && id <= 921999:
		return "Request Integrity"
	case id >= 930000 && id <= 930999:
		return "File System Protection"
	case id >= 931000 && id <= 931999:
		return "Remote Resource Access"
	case id >= 932000 && id <= 932999:
		return "Command Execution (RCE)"
	case id >= 933000 && id <= 933999:
		return "PHP Security"
	case id >= 934000 && id <= 934999:
		return "NodeJS Security"
	case id >= 941000 && id <= 941999:
		return "Script Injection (XSS)"
	case id >= 942000 && id <= 942999:
		return "Database Injection (SQLi)"
	case id >= 943000 && id <= 943999:
		return "Session Security"
	case id >= 944000 && id <= 944999:
		return "Java Security"
	case id >= 950000 && id <= 959999:
		return "Data Leakage (DLP)"
	default:
		return "Security Policy"
	}
}

func getWAFDetails(ruleID int, originalDetails string) (explanation, recommendation string) {
	if info, ok := crsRuleExplanations[ruleID]; ok {
		return info.Explanation, info.Recommendation
	}
	if originalDetails == "" {
		originalDetails = fmt.Sprintf("Rule %d triggered a security block.", ruleID)
	}
	return originalDetails, "Review the security logs for more details or contact your administrator if you believe this is a false positive."
}

func generateSmartInsight(t types.Transaction, it *types.Interruption) (explanation, recommendation, triggeredRules string) {
	if it == nil {
		return "", "", ""
	}
	matchedRules := t.MatchedRules()
	ruleID := it.RuleID

	// Default values
	explanation, recommendation = getWAFDetails(ruleID, "")
	attackRules := make([]int, 0)

	var detailsSb strings.Builder

	// If it's the Anomaly Score rule, we aggregate everything.
	if ruleID == 949110 {
		detailsSb.WriteString("Request blocked due to suspicious patterns. The following violations were found:\n")

		// Group by category for better readability
		byCategory := make(map[string][]string)
		highParanoia := false

		for _, mr := range matchedRules {
			id := mr.Rule().ID()
			// Skip internal/setup/reporting rules to avoid noise
			if id == 949110 || (id >= 900000 && id <= 901999) || (id >= 1900000 && id <= 1901999) || (id >= 99000 && id <= 99999) || (id >= 949000 && id <= 949999) || (id >= 980000 && id <= 980999) {
				continue
			}

			// Detect high paranoia level rules (usually ending in 13, 14, 15... or having it in the msg)
			if strings.Contains(strings.ToLower(mr.Message()), "paranoia") || id%100 >= 13 {
				highParanoia = true
			}

			attackRules = append(attackRules, id)

			location := "unknown location"
			if len(mr.MatchedDatas()) > 0 {
				md := mr.MatchedDatas()[0]
				varName := md.Variable().Name()
				if key := md.Key(); key != "" {
					location = fmt.Sprintf("'%s' in %s", key, varName)
				} else {
					location = varName
				}
			}

			msg := mr.Message()
			if msg == "" {
				if info, ok := crsRuleExplanations[id]; ok {
					msg = info.Explanation
				}
			}
			if msg == "" {
				msg = "Suspicious pattern detected"
			}

			cat := getRuleCategory(id)
			item := fmt.Sprintf("• %s (Rule %d, at %s)", msg, id, location)
			byCategory[cat] = append(byCategory[cat], item)
		}

		// Sort categories to have consistent output
		cats := make([]string, 0, len(byCategory))
		for k := range byCategory {
			cats = append(cats, k)
		}
		slices.Sort(cats)

		for _, cat := range cats {
			fmt.Fprintf(&detailsSb, "\n[%s]\n", cat)
			for _, item := range byCategory[cat] {
				detailsSb.WriteString(item + "\n")
			}
		}

		explanation = detailsSb.String()

		// Context-aware recommendation
		uri := ""
		if len(matchedRules) > 0 {
			uri = matchedRules[0].URI()
		}
		uriLower := strings.ToLower(uri)

		// Path-specific recommendations
		pathRec := ""
		if strings.Contains(uriLower, "token") || strings.Contains(uriLower, "refresh") || strings.Contains(uriLower, "login") || strings.Contains(uriLower, "auth") {
			pathRec = "This endpoint handles sensitive authentication data. Cryptographic tokens often look like database or script attacks. If this is legitimate traffic, click 'Mark as False Positive' to automatically whitelist these patterns for this path."
		} else if containsUUID(uri) {
			pathRec = "This path contains a UUID or complex identifier. These can sometimes trigger false positives in path-based security rules (like Rule 941010). If this is legitimate traffic, use the 'Mark as False Positive' button to create a targeted exclusion."
		} else {
			pathRec = "Review the violations above. If these are expected behaviors for your application, use the 'Mark as False Positive' button to create a targeted exclusion and restore the client's reputation."
		}

		if pathRec != "" {
			recommendation = pathRec
		}

		if highParanoia {
			recommendation += "\n\nHint: Multiple high-paranoia rules were triggered. These rules are very strict and often cause false positives. If this traffic is legitimate, consider lowering the CRS Paranoia Level in settings."
		} else if len(attackRules) > 3 {
			recommendation += "\n\nHint: Multiple security violations detected. This usually indicates either a complex false positive or a multi-stage attack."
		}
	} else {
		// Single rule block
		var mr types.MatchedRule
		for _, r := range matchedRules {
			if r.Rule().ID() == ruleID {
				mr = r
				break
			}
		}

		if mr != nil {
			attackRules = append(attackRules, ruleID)

			msg := mr.Message()
			if msg == "" {
				if info, ok := crsRuleExplanations[ruleID]; ok {
					msg = info.Explanation
				}
			}
			if msg == "" {
				msg = "Security signature match"
			}

			if len(mr.MatchedDatas()) > 0 {
				md := mr.MatchedDatas()[0]
				val := md.Value()
				if len(val) > 50 {
					val = val[:47] + "..."
				}
				explanation = fmt.Sprintf("Security violation: %s (Rule %d). The value '%s' at %s matched a known threat signature.", msg, ruleID, val, md.Variable().Name())

				// Smart Token Detection in matched data:
				for _, md := range mr.MatchedDatas() {
					v := md.Value()
					if len(v) > 80 && (isJWT(v) || isPaseto(v) || entropy.CalculateString(v) > 4.5) {
						recommendation += "\nSmart Insight: The blocked value appears to be a legitimate security token or cryptographic hash. Use the 'Mark as False Positive' button to automatically create a targeted exclusion for this field."
						break
					}
				}
			}
		}
	}

	// Add fingerprint/entropy insights if recorded in context (for fast-path threats)
	// ... (rest of the switch stays the same)
	if ca, ok := t.(interface {
		GetCollection(variables.RuleVariable) collection.Collection
	}); ok {
		if tx, ok := ca.GetCollection(variables.TX).(collection.Keyed); ok {
			if typeStr := tx.Get("fast_path_type"); len(typeStr) > 0 {
				switch typeStr[0] {
				case "fast_path_entropy":
					explanation = "High Shannon Entropy detected in request components, suggesting obfuscated shellcode, encrypted payloads, or binary injection."
					recommendation = "Review the flagged field for unusual character distributions. If this is legitimate binary data, consider whitelisting the field or endpoint."
				case "fast_path_fingerprint":
					explanation = "Client fingerprint mismatch: The TLS/HTTP fingerprint does not match the declared User-Agent, indicating a spoofed client or automated bot."
					recommendation = "The request appears to be coming from a tool masquerading as a browser. Verify the legitimacy of the client or enforce CAPTCHA/JS challenges."
				case "fast_path_protocol_violation":
					explanation = "HTTP/2 or HTTP/3 protocol violation detected (e.g., forbidden 'Connection' header). This is common in poorly implemented bots or exploit scripts."
					recommendation = "Check if the client is using an outdated or non-standard HTTP library. Legitimate browsers do not violate these protocol rules."
				case "fast_path_suspicious_client":
					explanation = "The client claims to be a modern browser but is missing mandatory headers like 'Accept-Encoding', suggesting a scripted attack."
					recommendation = "Review the client's traffic patterns. If this is a legitimate automated tool, ensure it sends standard browser-like headers."
				case "fast_path_malformed_token":
					explanation = "Malformed security token structure detected in the Authorization header."
					recommendation = "Ensure your client is sending a valid security token (JWT, Paseto). If you are using a custom token format, you may need to adjust the Gateon Fast-Path settings."
				}
			}
		}
	}

	if len(attackRules) > 0 {
		if b, err := json.Marshal(attackRules); err == nil {
			triggeredRules = string(b)
		}
	}

	return explanation, recommendation, triggeredRules
}

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

// WAF returns a middleware that applies OWASP Coraza WAF with optional CRS.
func WAF(cfg WAFConfig) (Middleware, error) {
	// createWAFInstance correctly uses WafRules if provided.
	waf, err := createWAFInstance(cfg)
	if err != nil {
		return nil, err
	}

	wrappedWaf := &wafWrapper{waf: waf, routeID: cfg.RouteID, cfg: cfg}

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

			// 4. Cloudflare IP trust
			if cfg.TrustCloudflare {
				clientIP := request.GetClientIP(r, true)
				if last := strings.LastIndexByte(r.RemoteAddr, ':'); last != -1 && !strings.HasSuffix(r.RemoteAddr, "]") {
					r.RemoteAddr = clientIP + r.RemoteAddr[last:]
				} else {
					r.RemoteAddr = clientIP
				}
			}

			grpcRequest := cfg.GRPCMode && isGRPCRequest(r)

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

			// 6. Fast Path Signature & Entropy checks
			if !grpcRequest {
				rawURI := r.RequestURI
				if matches := fastScanner.FindAll(rawURI); len(matches) > 0 {
					details := "Request URI match: " + strings.Join(matches, ", ")
					recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
					if !cfg.AuditOnly {
						http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
						return
					}
				}

				unescapedURI, _ := url.PathUnescape(rawURI)
				if unescapedURI != "" && unescapedURI != rawURI {
					if matches := fastScanner.FindAll(unescapedURI); len(matches) > 0 {
						details := "Unescaped Request URI match: " + strings.Join(matches, ", ")
						recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
						if !cfg.AuditOnly {
							http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
							return
						}
					}
				}

				if referer := r.Header.Get("Referer"); referer != "" {
					if matches := fastScanner.FindAll(referer); len(matches) > 0 {
						details := "Referer header match: " + strings.Join(matches, ", ")
						recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
						if !cfg.AuditOnly {
							http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
							return
						}
					}
				}
				if ua := r.Header.Get("User-Agent"); ua != "" {
					if matches := fastScanner.FindAll(ua); len(matches) > 0 {
						details := "User-Agent header match: " + strings.Join(matches, ", ")
						recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
						if !cfg.AuditOnly {
							http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
							return
						}
					}
				}
			}

			// Check entropy of common fields to detect shellcode/obfuscation
			if !grpcRequest && !cfg.DisableEntropy {
				threshold := cfg.EntropyThreshold
				if threshold <= 0 {
					threshold = 5.8
				}
				// Adaptive Entropy: If reputation is high, increase threshold to reduce false positives
				if repScore > 90 {
					threshold += 0.5
				} else if repScore < 20 {
					threshold -= 0.5
				}

				for key, vals := range r.Header {
					if isSafeHeader(key) {
						continue
					}
					for _, val := range vals {
						// High entropy in unknown headers is still suspicious.
						if len(val) > 64 && entropy.IsSuspicious(val, threshold) {
							recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", fmt.Sprintf("High entropy in header %s: %.2f (threshold %.2f)", key, entropy.CalculateString(val), threshold))
							http.Error(w, "Forbidden by Security Fast-Path (High Entropy Detected)", http.StatusForbidden)
							return
						}
					}
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
			if cfg.EnableBodyEntropy && !grpcRequest && r.ContentLength > 0 && r.ContentLength < 1024*1024 {
				peeked, err := peekBody(r, 2048)
				if err == nil && len(peeked) > 64 {
					if rs != nil {
						rs.ExecutedEntropy = true
					}
					threshold := cfg.EntropyThreshold
					if threshold <= 0 {
						threshold = 5.8
					}
					// Adaptive Entropy: Content-Type awareness
					ct := strings.ToLower(r.Header.Get("Content-Type"))
					if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "form") {
						threshold += 0.2 // Allow slightly higher entropy for structured data
					}

					if repScore > 90 {
						threshold += 0.5
					} else if repScore < 20 {
						threshold -= 0.5
					}

					if entropy.IsSuspiciousBytes(peeked, threshold) {
						ent := entropy.Calculate(peeked)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", fmt.Sprintf("High entropy in request body: %.2f (threshold %.2f)", ent, threshold))
						http.Error(w, "Forbidden by Security Fast-Path (High Body Entropy Detected)", http.StatusForbidden)
						return
					}
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

			// Manual Transaction Management
			tx := wrappedWaf.NewTransaction()
			tx.(*txWrapper).r = r
			defer tx.ProcessLogging()
			defer tx.Close()

			// Process Request Headers & URI
			it, err := processRequest(tx, r)
			if err != nil {
				logger.L.LogError("WAF failed to process request", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if it != nil && !cfg.AuditOnly {
				status := it.Status
				if status == 0 {
					status = http.StatusForbidden
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("Forbidden by Security Policy (WAF)"))
				return
			}

			if !cfg.EnableResponseInspection || grpcRequest {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap ResponseWriter for Phase 3/4 (DLP / Response Inspection)
			// We buffer the response to allow changing status code if a rule matches in Phase 3/4.
			ww := &wafResponseWriter{
				ResponseWriter: w,
				tx:             tx,
				buf:            &bytes.Buffer{},
				auditOnly:      cfg.AuditOnly,
			}
			next.ServeHTTP(ww, r)
			if !ww.interrupted {
				// Process remaining body if any
				it, err := tx.ProcessResponseBody()
				if err == nil && it != nil && !cfg.AuditOnly {
					ww.interrupted = true
					ww.ResponseWriter.WriteHeader(http.StatusForbidden)
					_, _ = ww.ResponseWriter.Write([]byte("Forbidden by Security Policy (Response Blocked)"))
					return
				}
				// Flush buffer
				if ww.status == 0 {
					ww.status = http.StatusOK
				}
				// If not interrupted, write the original status and buffered body
				if !ww.headerWritten {
					w.WriteHeader(ww.status)
				}
				_, _ = w.Write(ww.buf.Bytes())
			}
		})
		return h
	}, nil
}

func createWAFInstance(cfg WAFConfig) (coraza.WAF, error) {
	wafConfig := coraza.NewWAFConfig()
	var sb strings.Builder

	// Build directives string... (existing logic)

	if cfg.UseCRS {
		pl := cfg.ParanoiaLevel
		if pl < 1 {
			pl = 1
		}
		if pl > 4 {
			pl = 4
		}
		engineDirective := "SecRuleEngine On\n"
		if cfg.AuditOnly {
			engineDirective = "SecRuleEngine DetectionOnly\n"
		}

		sb.WriteString(engineDirective)
		threshold := cfg.AnomalyThreshold
		if threshold <= 0 {
			threshold = 5
		}
		_, _ = fmt.Fprintf(&sb, `SecAction "id:99000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d"
SecWebAppId gateon
SecAction "id:99002,phase:1,nolog,pass,initcol:ip=%%{REMOTE_ADDR},setvar:tx.dos_burst_time_slice=60,setvar:tx.dos_counter_threshold=100,setvar:tx.dos_block_timeout=600"
Include @crs-setup.conf.example
`, pl)

		// Basic enforcement and common rules
		sb.WriteString("Include @owasp_crs/REQUEST-901-INITIALIZATION.conf\n")
		// Override defaults from CRS initialization with our configured thresholds
		_, _ = fmt.Fprintf(&sb, "SecAction \"id:99099,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", threshold, threshold)

		// Inject dynamic variables for rules (must be before loading database rules that use them)
		allowedIps := "127.0.0.1"
		if len(cfg.AllowedAdminIps) > 0 {
			allowedIps = strings.Join(append([]string{"127.0.0.1"}, cfg.AllowedAdminIps...), " ")
		}
		_, _ = fmt.Fprintf(&sb, "SecAction \"id:99005,phase:1,nolog,pass,setvar:tx.allowed_admin_ips=%s\"\n", allowedIps)

		if cfg.GRPCMode {
			sb.WriteString("SecAction \"id:99006,phase:1,nolog,pass,setvar:tx.grpc_mode=1\"\n")
		}

		// Load dynamic rules from database
		if cfg.WafRules != nil {
			rules := cfg.WafRules.GetEnabledRules()
			for _, r := range rules {
				if r.ParanoiaLevel <= pl {
					sb.WriteString(r.Directive)
					sb.WriteByte('\n')
				}
			}
		}

		if cfg.EnableIPReputation {
			sb.WriteString("SecRule REQUEST_HEADERS:X-Gateon-Ip-Reputation-Block \"@eq 1\" \"id:99201,phase:1,pass,log,msg:'IP Reputation hit',tag:'reputation',severity:CRITICAL,setvar:tx.anomaly_score=+5,setvar:tx.inbound_anomaly_score=+5\"\n")
		}

		sb.WriteString("Include @owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf\n")

		if !cfg.DisableProtocol {
			sb.WriteString("Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf\n")
			sb.WriteString("Include @owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n")
			sb.WriteString("Include @owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf\n")
		}
		if !cfg.DisableScanner {
			sb.WriteString("Include @owasp_crs/REQUEST-913-SCANNER-DETECTION.conf\n")
		}
		if !cfg.DisableLFI {
			sb.WriteString("Include @owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf\n")
			sb.WriteString("Include @owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf\n")
		}
		if !cfg.DisableRCE {
			sb.WriteString("Include @owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf\n")
		}
		if !cfg.DisablePHP {
			sb.WriteString("Include @owasp_crs/REQUEST-933-APPLICATION-ATTACK-PHP.conf\n")
		}
		if !cfg.DisableXSS {
			sb.WriteString("Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf\n")
		}
		if !cfg.DisableSQLI {
			sb.WriteString("Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\n")
		}
		sb.WriteString("Include @owasp_crs/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf\n")
		if !cfg.DisableJava {
			sb.WriteString("Include @owasp_crs/REQUEST-944-APPLICATION-ATTACK-JAVA.conf\n")
		}
		if !cfg.DisableNodeJS {
			sb.WriteString("Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf\n")
		}

		sb.WriteString("Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf\n")
		sb.WriteString("SecRuleUpdateActionById 949110 \"deny,status:403\"\n")
		// Manually add evaluation rules to ensure blocking if anomaly score is exceeded.
		// We check both ANOMALY_SCORE and inbound_anomaly_score just in case.
		sb.WriteString("SecRule TX:ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:99491,phase:2,deny,status:403,msg:'Inbound Anomaly Score Exceeded (Score: %{TX.ANOMALY_SCORE})',tag:'anomaly-evaluation'\"\n")
		sb.WriteString("SecRule TX:inbound_anomaly_score \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:99492,phase:2,deny,status:403,msg:'Inbound Anomaly Score Exceeded (Score: %{TX.inbound_anomaly_score})',tag:'anomaly-evaluation'\"\n")
		// Ensure immediate interruption for any high-severity attack regardless of score
		sb.WriteString("SecRule TX:sql_injection_score \"@ge 5\" \"id:99493,phase:2,deny,status:403,msg:'SQL Injection Detected',tag:'attack-sqli'\"\n")
		sb.WriteString("SecRule TX:xss_score \"@ge 5\" \"id:99494,phase:2,deny,status:403,msg:'XSS Detected',tag:'attack-xss'\"\n")

		if cfg.EnableResponseInspection {
			if cfg.EnableDLP {
				sb.WriteString("Include @owasp_crs/RESPONSE-950-DATA-LEAKAGES.conf\n")
			}
			if !cfg.DisableSQLI {
				sb.WriteString("Include @owasp_crs/RESPONSE-951-DATA-LEAKAGES-SQL.conf\n")
			}
			if !cfg.DisableJava {
				sb.WriteString("Include @owasp_crs/RESPONSE-952-DATA-LEAKAGES-JAVA.conf\n")
			}
			if !cfg.DisablePHP {
				sb.WriteString("Include @owasp_crs/RESPONSE-953-DATA-LEAKAGES-PHP.conf\n")
			}
			sb.WriteString("Include @owasp_crs/RESPONSE-954-DATA-LEAKAGES-IIS.conf\n")
			sb.WriteString("Include @owasp_crs/RESPONSE-959-BLOCKING-EVALUATION.conf\n")
			sb.WriteString("SecRuleUpdateActionById 959100 \"deny,status:403\"\n")
			sb.WriteString("Include @owasp_crs/RESPONSE-980-CORRELATION.conf\n")
		}

		if cfg.RulesPath != "" {
			wafConfig = wafConfig.WithRootFS(os.DirFS(cfg.RulesPath))
		} else {
			wafConfig = wafConfig.WithRootFS(fsWrapper{coreruleset.FS})
		}
	}

	if auditPath := resolveAuditLogPath(cfg); auditPath != "" {
		if err := ensureAuditLogFile(auditPath); err == nil {
			auditEngine := "On"
			if cfg.AuditLogRelevantOnly {
				auditEngine = "RelevantOnly"
			}
			_, _ = fmt.Fprintf(&sb, `
SecAuditEngine %s
SecAuditLogParts ABIJDEFHKZ
SecAuditLogType Serial
SecAuditLog "%s"
`, auditEngine, strings.ReplaceAll(auditPath, "\\", "/"))
		}
	}

	if sb.Len() > 0 {
		wafConfig = wafConfig.WithDirectives(sb.String())
	}
	if cfg.GlobalDirectives != "" {
		wafConfig = wafConfig.WithDirectives(cfg.GlobalDirectives)
	}
	if cfg.Directives != "" {
		wafConfig = wafConfig.WithDirectives(cfg.Directives)
	}
	if cfg.DirectivesFile != "" {
		wafConfig = wafConfig.WithDirectivesFromFile(cfg.DirectivesFile)
	} else if !cfg.UseCRS && cfg.Directives == "" {
		wafConfig = wafConfig.WithDirectives(`SecRuleEngine Off`)
	}

	if cfg.RequestBodyLimit > 0 || cfg.EnableMalwareDetection || cfg.EnableRansomwareDetection {
		limit := cfg.RequestBodyLimit
		if limit <= 0 {
			limit = 10 * 1024 * 1024
		}
		wafConfig = wafConfig.WithRequestBodyLimit(limit)
		memLimit := int64(limit) / 10
		if memLimit < 1024*1024 {
			memLimit = 1024 * 1024
		}
		memLimit = min(memLimit, int64(limit))
		wafConfig = wafConfig.WithRequestBodyInMemoryLimit(int(memLimit))
		wafConfig = wafConfig.WithDirectives("SecRequestBodyAccess On")
	}

	if cfg.EnableResponseInspection && cfg.ResponseBodyLimit > 0 {
		wafConfig = wafConfig.WithResponseBodyLimit(cfg.ResponseBodyLimit)
		wafConfig = wafConfig.WithDirectives("SecResponseBodyAccess On")
		wafConfig = wafConfig.WithDirectives(`SecResponseBodyMimeType text/plain text/html text/xml application/json application/xml application/xhtml+xml`)
	}

	// Create a unique key for the compiled WAF instance based on all directives
	// and critical settings. This allows multiple routes to share the same
	// expensive-to-compile WAF instance.
	h := hashPool.Get().(hash.Hash)
	h.Reset()
	defer hashPool.Put(h)

	// Hash all directives in order
	io.WriteString(h, sb.String())
	io.WriteString(h, cfg.GlobalDirectives)
	io.WriteString(h, cfg.Directives)
	io.WriteString(h, cfg.DirectivesFile)
	if cfg.RequestBodyLimit > 0 {
		_, _ = fmt.Fprintf(h, "|reqLimit:%d", cfg.RequestBodyLimit)
	}
	if cfg.ResponseBodyLimit > 0 {
		_, _ = fmt.Fprintf(h, "|respLimit:%d", cfg.ResponseBodyLimit)
	}
	key := hex.EncodeToString(h.Sum(nil))

	if val, ok := wafInstanceCache.Load(key); ok {
		return val.(coraza.WAF), nil
	}

	wafConfig = wafConfig.WithErrorCallback(func(mr types.MatchedRule) {
		ruleID := strconv.Itoa(mr.Rule().ID())
		logger.L.LogWarn("WAF matched rule",
			"event", "waf_match",
			"rule_id", ruleID,
			"client_ip", mr.ClientIPAddress(),
			"uri", mr.URI(),
			"severity", mr.Rule().Severity().String(),
			"message", mr.ErrorLog())
	})

	instance, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, err
	}

	// Store in cache (or use existing if someone beat us to it)
	if actual, loaded := wafInstanceCache.LoadOrStore(key, instance); loaded {
		return actual.(coraza.WAF), nil
	}

	return instance, nil
}

// recordFastPathThreat records a security threat detected by the fast-path.
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
	if typeStr == "fast_path_signature" {
		rules = "[1900001]"
	} else if typeStr == "fast_path_malformed_token" {
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
	lname := strings.ToLower(name)
	if safeHeaders[lname] {
		return true
	}

	return false
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

type wafWrapper struct {
	mu      sync.RWMutex
	waf     coraza.WAF
	routeID string
	cfg     WAFConfig
}

func (w *wafWrapper) NewTransaction() types.Transaction {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return &txWrapper{
		Transaction: w.waf.NewTransaction(),
		routeID:     w.routeID,
		cfg:         w.cfg,
	}
}

func (w *wafWrapper) NewTransactionWithID(id string) types.Transaction {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return &txWrapper{
		Transaction: w.waf.NewTransactionWithID(id),
		routeID:     w.routeID,
		cfg:         w.cfg,
	}
}

type txWrapper struct {
	types.Transaction
	ctx     context.Context
	r       *http.Request
	routeID string
	cfg     WAFConfig
}

func (t *txWrapper) ProcessLogging() {
	fingerprint := ""
	ja4 := ""
	ja4h := ""
	if t.r != nil {
		if rs := request.GetRequestState(t.r); rs != nil {
			fingerprint = rs.JA4Plus
			ja4 = rs.JA4
			ja4h = rs.JA4H
		}
	}
	interrupted := t.IsInterrupted()
	var it *types.Interruption
	if interrupted {
		it = t.Interruption()
		logger.L.LogInfo("WAF Transaction Interrupted", "rule_id", it.RuleID, "action", it.Action, "route", t.routeID)
	}
	matchedRules := t.MatchedRules()
	if len(matchedRules) > 0 {
		anomalyScore := 0
		clientIP := ""
		uri := ""
		severity := "notice"
		category := "general"
		repScore := 100.0
		ua := ""
		method := ""
		isCritical := false
		details := ""

		if ca, ok := t.Transaction.(interface {
			GetCollection(variables.RuleVariable) collection.Collection
		}); ok {
			if c, ok := ca.GetCollection(variables.TX).(collection.Keyed); ok {
				// Thoroughly check for anomaly scores
				findScore := func(name string) int {
					if vals := c.Get(name); len(vals) > 0 {
						s, _ := strconv.Atoi(vals[0])
						return s
					}
					return 0
				}

				anomalyScore = findScore("anomaly_score")
				if s := findScore("inbound_anomaly_score"); s > anomalyScore {
					anomalyScore = s
				}
				// CRS v4 specific scores
				for i := 1; i <= 4; i++ {
					if s := findScore(fmt.Sprintf("anomaly_score_pl%d", i)); s > anomalyScore {
						anomalyScore = s
					}
				}
			}

			if c, ok := ca.GetCollection(variables.RequestHeaders).(collection.Keyed); ok {
				if vals := c.Get("X-Gateon-Reputation"); len(vals) > 0 {
					if f, err := strconv.ParseFloat(vals[0], 64); err == nil {
						repScore = f
					}
				}
				if vals := c.Get("X-Gateon-JA4"); len(vals) > 0 && ja4 == "" {
					ja4 = vals[0]
				}
				if fingerprint == "" && ja4 != "" {
					if ja4h == "" && t.r != nil {
						ja4h = telemetry.GetCachedJA4H(t.r)
					}
					fingerprint = ja4 + "_" + ja4h
				}
				if vals := c.Get("User-Agent"); len(vals) > 0 {
					ua = vals[0]
				}
			}

			if c, ok := ca.GetCollection(variables.RequestMethod).(collection.Single); ok {
				method = c.Get()
			}
		}

		logger.L.LogInfo("WAF Rules Matched",
			"count", len(matchedRules),
			"anomaly_score", anomalyScore,
			"interrupted", interrupted,
			"route", t.routeID,
			"threshold", t.cfg.AnomalyThreshold)

		if anomalyScore == 0 && !interrupted {
			// Ensure reputation hits are always recorded even if anomaly score is 0
			isReputation := false
			for _, rule := range matchedRules {
				tags := rule.Rule().Tags()
				for _, tag := range tags {
					if strings.Contains(strings.ToLower(tag), "reputation") {
						isReputation = true
						break
					}
				}
				if isReputation {
					break
				}
			}
			if !isReputation {
				return
			}
		}

		for _, rule := range matchedRules {
			if clientIP == "" {
				clientIP = rule.ClientIPAddress()
			}
			if uri == "" {
				uri = rule.URI()
			}
			if rule.Rule().Severity() <= types.RuleSeverityCritical {
				isCritical = true
			}

			// Optimized: identify category from tags in a single pass
			if category == "general" || category == "" {
				category = getCategoryFromTags(rule.Rule().Tags())
			}

			if interrupted && rule.Rule().ID() == it.RuleID {
				severity = strings.ToLower(rule.Rule().Severity().String())
				details = rule.ErrorLog()
			}
		}

		if details == "" {
			// Fallback to last matched rule if the interrupting one isn't in matched rules
			// OR if not interrupted at all.
			last := matchedRules[len(matchedRules)-1]
			details = last.ErrorLog()
			if clientIP == "" {
				clientIP = last.ClientIPAddress()
			}
			if uri == "" {
				uri = last.URI()
			}
		}

		if interrupted {
			ruleID := strconv.Itoa(it.RuleID)
			telemetry.RequestFailuresTotal.WithLabelValues(t.routeID, "waf:"+ruleID).Inc()
		}

		if clientIP != "" && interrupted {
			telemetry.GetAggregator().RecordWAFBlock(clientIP)

			// IPS feature: automatically shun IPs at L3/L4 via eBPF.
			if t.cfg.EbpfManager != nil && isCritical {
				shouldShun := repScore < 50 || anomalyScore >= 20 || !t.cfg.UseCRS
				if !shouldShun {
					for _, rule := range matchedRules {
						id := rule.Rule().ID()
						if id >= 100001 && id <= 100013 {
							shouldShun = true
							break
						}
					}
				}

				if shouldShun && clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost" {
					// We no longer shun IPs at the kernel level by default to avoid blocking
					// innocent users on shared IPs (NAT/CGNAT).
					// Instead, we rely on WAF's L7 block and the fingerprint-based mitigation
					// recorded below, which is more precise and follows the JA4+ blocking policy.
					// _ = t.cfg.EbpfManager.ShunIP(clientIP)
				} else if anomalyScore >= 10 && clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost" {
					_ = t.cfg.EbpfManager.SetAdaptiveRateLimit(clientIP, time.Second)
				}
			}
		}

		// Record security threat for telemetry and UI
		explanation, recommendation, triggeredRules := generateSmartInsight(t.Transaction, it)
		telemetry.RegisterRecommendation(t.ID(), recommendation)

		confidence := 0.8
		ent := 0.0
		for _, mr := range matchedRules {
			for _, md := range mr.MatchedDatas() {
				if v := md.Value(); len(v) > 0 {
					e := entropy.CalculateString(v)
					if e > ent {
						ent = e
					}
				}
			}
		}

		if t.cfg.EnableConfidenceScoring {
			confidence = calculateConfidence(repScore, severity, anomalyScore, false)
		}

		actionTaken := "detected"
		if interrupted {
			actionTaken = "blocked"
		}

		telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(t.r, telemetry.SecurityThreat{
			ID:             fmt.Sprintf("waf-%s-%s", actionTaken, t.ID()),
			Type:           "waf_" + actionTaken,
			SourceIP:       clientIP,
			Fingerprint:    fingerprint,
			Score:          100, // Explicit block is a high priority threat
			Details:        explanation,
			Recommendation: recommendation,
			Time:           time.Now(),
			RouteID:        t.routeID,
			RequestURI:     uri,
			Category:       category,
			Severity:       severity,
			ActionTaken:    actionTaken,
			Mitigated:      interrupted,
			JA4:            ja4,
			JA4H:           ja4h,
			UserAgent:      ua,
			Method:         method,
			Confidence:     confidence,
			Entropy:        ent,
			TriggeredRules: triggeredRules,
		}))
	}
	t.Transaction.ProcessLogging()
}

// fsWrapper wraps an fs.FS to convert backslashes to forward slashes,
// which is required for embed.FS to work correctly on Windows.
type fsWrapper struct {
	fs.FS
}

func (f fsWrapper) Open(name string) (fs.File, error) {
	return f.FS.Open(strings.ReplaceAll(name, "\\", "/"))
}

// resolveAuditLogPath returns the audit log path to use. When the operator left
// the field blank it derives a stable default under the Gateon data directory so
// auditing "just works" without anyone having to hand-pick a writable path.
func resolveAuditLogPath(cfg WAFConfig) string {
	if p := strings.TrimSpace(cfg.AuditLogPath); p != "" {
		return p
	}
	name := sanitizeAuditName(cfg.RouteID)
	if name == "" {
		name = "waf"
	}
	return filepath.Join(config.DataDir(), "audit", "waf", name+"_audit.log")
}

// sanitizeAuditName makes a route/middleware identifier safe to use as a filename
// component (no path separators or other surprising characters).
func sanitizeAuditName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "._")
}

// ensureAuditLogFile creates the audit log's parent directory and the file itself
// if they do not yet exist, so Coraza's SecAuditLog directive has somewhere to
// write. It is idempotent and safe to call on every (re)build of the WAF.
func ensureAuditLogFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create audit log dir %q: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("create audit log file %q: %w", path, err)
	}
	return f.Close()
}

// parseWAFConfig parses middleware config map into WAFConfig.
func parseWAFConfig(cfg map[string]string) WAFConfig {
	useCRS := true
	if v, ok := cfg["use_crs"]; ok {
		useCRS = strings.TrimSpace(strings.ToLower(v)) != "false"
	}
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

	return WAFConfig{
		UseCRS:                      useCRS,
		ParanoiaLevel:               pl,
		Directives:                  strings.TrimSpace(cfg["directives"]),
		DirectivesFile:              strings.TrimSpace(cfg["directives_file"]),
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
		RequestBodyLimit:            intVal(cfg["request_body_limit"]),
		ResponseBodyLimit:           intVal(cfg["response_body_limit"]),
		AuditLogPath:                strings.TrimSpace(cfg["audit_log_path"]),
		AuditLogRelevantOnly:        strings.TrimSpace(strings.ToLower(cfg["audit_log_relevant_only"])) != "false",
		RouteID:                     routeID,
		AllowedAdminIps:             allowedAdminIps,
		RulesPath:                   strings.TrimSpace(cfg["rules_path"]),
	}
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

func getCategoryFromTags(tags []string) string {
	for _, tag := range tags {
		// Optimization: avoid ToLower allocation if possible, or use a smaller set of checks.
		t := strings.ToLower(tag)
		if strings.Contains(t, "sqli") {
			return "sqli"
		}
		if strings.Contains(t, "xss") {
			return "xss"
		}
		if strings.Contains(t, "rce") || strings.Contains(t, "php") || strings.Contains(t, "injection") {
			return "rce"
		}
		if strings.Contains(t, "lfi") {
			return "lfi"
		}
		if strings.Contains(t, "scanner") || strings.Contains(t, "bot") {
			return "bot"
		}
		if strings.Contains(t, "protocol") {
			return "protocol"
		}
		if strings.Contains(t, "wordpress") || strings.Contains(t, "wp_scan") {
			return "wp_scan"
		}
		if strings.Contains(t, "malware") {
			return "malware"
		}
		if strings.Contains(t, "ransomware") {
			return "ransomware"
		}
		if strings.Contains(t, "reputation") {
			return "reputation"
		}
	}
	return "general"
}

func containsUUID(s string) bool {
	// A standard UUID has 36 characters and 4 hyphens: 8-4-4-4-12
	// We look for this pattern heuristically.
	count := 0
	for _, r := range s {
		if r == '-' {
			count++
		}
	}
	if count < 4 {
		return false
	}
	// Check for hex segments
	parts := strings.Split(s, "/")
	for _, p := range parts {
		if len(p) == 36 && strings.Count(p, "-") == 4 {
			return true
		}
	}
	return false
}

func processRequest(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	// 1. Process Connection
	clientIP, clientPort := splitAddr(r.RemoteAddr)
	serverIP, serverPort := splitAddr(r.Host)
	tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)

	// 2. Process URI
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

	// 3. Add Request Headers
	for k, v := range r.Header {
		for _, vv := range v {
			tx.AddRequestHeader(k, vv)
		}
	}

	// 4. Add GET Arguments (required for ARGS_GET)
	// Optimized: Parse RawQuery manually to avoid map[string][]string allocations from r.URL.Query()
	rawQuery := r.URL.RawQuery
	for rawQuery != "" {
		key := rawQuery
		if i := strings.IndexAny(key, "&;"); i >= 0 {
			key, rawQuery = key[:i], key[i+1:]
		} else {
			rawQuery = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		k, _ := url.QueryUnescape(key)
		v, _ := url.QueryUnescape(value)
		tx.AddGetRequestArgument(k, v)
	}

	// 5. Process Request Headers
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	// 6. Process Request Body (triggers Phase 2)
	// Skip request body inspection for gRPC and known safe large traffic if reputation is high.
	if r.Body != nil && r.Body != http.NoBody && !isGRPCRequest(r) {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
	}

	return tx.ProcessRequestBody()
}

type wafResponseWriter struct {
	http.ResponseWriter
	tx            types.Transaction
	status        int
	buf           *bytes.Buffer
	interrupted   bool
	headerWritten bool
	auditOnly     bool
}

func (w *wafResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *wafResponseWriter) WriteHeader(status int) {
	if w.interrupted || w.headerWritten {
		return
	}
	w.status = status
	// We don't call w.ResponseWriter.WriteHeader yet because we might need to change it to 403
	// but we must process headers in Coraza
	for k, vv := range w.Header() {
		for _, v := range vv {
			w.tx.AddResponseHeader(k, v)
		}
	}
	it := w.tx.ProcessResponseHeaders(status, "HTTP/1.1")
	if it != nil && !w.auditOnly {
		w.interrupted = true
		w.headerWritten = true
		w.ResponseWriter.WriteHeader(http.StatusForbidden)
		_, _ = w.ResponseWriter.Write([]byte("Forbidden by Security Policy (Response Header Blocked)"))
		return
	}
}

func (w *wafResponseWriter) Write(b []byte) (int, error) {
	if w.interrupted {
		return 0, nil
	}
	if !w.headerWritten && !w.interrupted && w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.interrupted {
		return 0, nil
	}

	it, _, err := w.tx.WriteResponseBody(b)
	if err == nil && it != nil && !w.auditOnly {
		w.interrupted = true
		if !w.headerWritten {
			w.headerWritten = true
			w.ResponseWriter.WriteHeader(http.StatusForbidden)
			_, _ = w.ResponseWriter.Write([]byte("Forbidden by Security Policy (Response Body Blocked)"))
		}
		return 0, fmt.Errorf("interrupted")
	}
	return w.buf.Write(b)
}

func (w *wafResponseWriter) Status() int {
	if w.status == 0 {
		return 200
	}
	return w.status
}

func (w *wafResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("response writer does not support hijacking")
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
