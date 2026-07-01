package middleware

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	txhttp "github.com/corazawaf/coraza/v3/http"
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
	EnableFingerprintValidation bool    // Enable JA3/JA4 fingerprint consistency check
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

// grpcCompatDirective makes the OWASP CRS Protocol-Enforcement rules compatible
// with the gRPC / gRPC-Web transport. It MUST be loaded after
// REQUEST-901-INITIALIZATION (which seeds the defaults it overrides) and before
// REQUEST-920-PROTOCOL-ENFORCEMENT (whose rules read those values / are removed
// here). All directives are phase:1 and run in load order, so they take effect
// before 920 evaluates and before phase:2 body processing. Ids sit in the
// reserved user range (900200+) and do not collide with the 9000xx setup actions.
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

	fastScanner = scanner.NewScanner([]string{
		"SELECT ", "UNION ", "INSERT ", "DELETE ", "UPDATE ", "DROP ", "EXEC ", // SQLi
		"<script", "javascript:", "onload=", "onerror=", "eval(", "atob(", "alert(", // XSS
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
			if id == 949110 || (id >= 900000 && id <= 901999) || (id >= 949000 && id <= 949999) || (id >= 980000 && id <= 980999) {
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
					if len(v) > 80 && (isJWT(v) || entropy.CalculateString(v) > 4.5) {
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
					explanation = "Malformed security token (JWT) structure detected in the Authorization header."
					recommendation = "Ensure your client is sending a valid JWT. If you are using a custom token format, you may need to adjust the Gateon Fast-Path settings."
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
	wafConfig := coraza.NewWAFConfig()
	var sb strings.Builder

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
			engineDirective = `SecRuleEngine DetectionOnly
`
		}

		sb.WriteString(engineDirective)
		_, _ = fmt.Fprintf(&sb, `SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d"
Include @crs-setup.conf.example
`, pl)

		// Basic enforcement and common rules
		sb.WriteString("Include @owasp_crs/REQUEST-901-INITIALIZATION.conf\n")

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

		sb.WriteString("Include @owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf\n")

		// gRPC compatibility is now loaded from database

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
			// In CRS 4.0, NodeJS attacks are covered by the Generic Attacks ruleset
			sb.WriteString("Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf\n")
		}
		if cfg.EnableIPReputation {
			// Rules are now loaded from database
		}
		if cfg.EnableDOSProtection {
			// Rules are now loaded from database
		}

		// Inject dynamic variables for rules
		allowedIps := "127.0.0.1"
		if len(cfg.AllowedAdminIps) > 0 {
			allowedIps = strings.Join(append([]string{"127.0.0.1"}, cfg.AllowedAdminIps...), " ")
		}
		_, _ = fmt.Fprintf(&sb, "SecAction \"id:900005,phase:1,nolog,pass,setvar:tx.allowed_admin_ips=%s\"\n", allowedIps)

		// WP Scanning and Exploits are now loaded from database
		// Ransomware protection is now loaded from database
		sb.WriteString("Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf\n")
		// Explicitly set the block status to 403 for the evaluation rules to avoid status 0 in audit logs
		// and 520 errors in Cloudflare.
		sb.WriteString("SecRuleUpdateActionById 949110 \"deny,status:403\"\n")

		// Response rules (RESPONSE-phase). These buffer response bodies, the most
		// expensive part of the WAF, so they are only loaded when response
		// inspection is enabled (enterprise tier). When off we skip the whole
		// response phase, avoiding response buffering entirely.
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

	// Coraza will not create the audit log's directory or file on its own; if the
	// path doesn't already exist it silently fails to write. So Gateon resolves a
	// sensible default when the operator leaves the field blank and provisions the
	// folder + file here. A provisioning failure only disables the audit directive
	// (e.g. read-only filesystem) — it never fails the whole WAF.
	if auditPath := resolveAuditLogPath(cfg); auditPath != "" {
		if err := ensureAuditLogFile(auditPath); err != nil {
			logger.L.LogError("waf: could not provision audit log; auditing disabled for this WAF",
				"path", auditPath, "route", cfg.RouteID, "error", err)
		} else {
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
		// Minimal pass-through when neither CRS nor custom directives
		wafConfig = wafConfig.WithDirectives(`SecRuleEngine Off`)
	}

	if cfg.RequestBodyLimit > 0 || cfg.EnableMalwareDetection || cfg.EnableRansomwareDetection {
		limit := cfg.RequestBodyLimit
		if limit <= 0 {
			limit = 10 * 1024 * 1024 // Default to 10MB if malware detection is on but no limit set
		}
		wafConfig = wafConfig.WithRequestBodyLimit(limit)
		// Also set in-memory limit to 10% of total limit or 1MB min, but not exceeding the total limit
		memLimit := int64(limit) / 10
		if memLimit < 1024*1024 {
			memLimit = 1024 * 1024
		}
		memLimit = min(memLimit, int64(limit))
		wafConfig = wafConfig.WithRequestBodyInMemoryLimit(int(memLimit))
		wafConfig = wafConfig.WithDirectives("SecRequestBodyAccess On")
	}
	// Response body access is only meaningful (and only worth its buffering cost)
	// when the RESPONSE-phase rules are loaded.
	if cfg.EnableResponseInspection && cfg.ResponseBodyLimit > 0 {
		wafConfig = wafConfig.WithResponseBodyLimit(cfg.ResponseBodyLimit)
		wafConfig = wafConfig.WithDirectives("SecResponseBodyAccess On")
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

		// Shunning is now handled in txWrapper.Close() with better heuristics
		// to avoid false-positive L3/L4 blocks for reputable users.
	})

	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("create WAF: %w", err)
	}

	wrappedWaf := &wafWrapper{WAF: waf, routeID: cfg.RouteID, cfg: cfg}

	return func(next http.Handler) http.Handler {
		wafHandler := txhttp.WrapHandler(wrappedWaf, next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ensure Host header is correctly set for Coraza and downstream services.
			// If r.Host is empty, Coraza logs empty hostname.
			if r.Host == "" && r.Header.Get("Host") != "" {
				r.Host = r.Header.Get("Host")
			}
			if r.Host != "" {
				// Standard Go http.Request.Header usually omits the Host header,
				// but Coraza's txhttp wrapper iterates over the Header map.
				// We force it here to ensure Coraza sees the hostname.
				r.Header["Host"] = []string{r.Host}
			}

			// Security Header Spoofing Prevention: clear internal headers from incoming request.
			r.Header.Del("X-Gateon-Reputation")
			r.Header.Del("X-Gateon-Anomaly-Score")
			r.Header.Del("X-Gateon-Threat-Type")
			r.Header.Del("X-Gateon-WAF-Matched")
			r.Header.Del("X-Gateon-JA4")

			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.TrustCloudflare {
				clientIP := request.GetClientIP(r, true)
				if last := strings.LastIndexByte(r.RemoteAddr, ':'); last != -1 && !strings.HasSuffix(r.RemoteAddr, "]") {
					r.RemoteAddr = clientIP + r.RemoteAddr[last:]
				} else {
					r.RemoteAddr = clientIP
				}
			}

			// gRPC transport carries binary protobuf framing and binary "-bin"
			// metadata headers that are inherently high-entropy and meaningless to
			// the byte-signature / entropy fast-paths, which would otherwise return
			// a spurious 403. Skip the fast-paths for gRPC; the CRS engine below
			// still inspects gRPC headers and the request URI. This is gated on the
			// trusted route type (cfg.GRPCMode) AND the request actually being gRPC,
			// so a spoofed Content-Type on a non-gRPC route cannot skip the scanners.
			grpcRequest := cfg.GRPCMode && isGRPCRequest(r)

			// Adaptive WAF: Adjust anomaly threshold based on client reputation
			fingerprint := telemetry.GetFingerprintHash(r)
			reputation := telemetry.GetReputationScore(fingerprint)
			// Use cached string to avoid allocation
			r.Header.Set("X-Gateon-Reputation", getReputationString(reputation))
			r.Header.Set("X-Gateon-JA4", telemetry.GetCachedJA4H(r))

			// GitLab Git-over-HTTP Bypass: Git pushes can be massive (GBs) and are
			// structurally incompatible with the buffering required for deep body
			// inspection. We trust highly reputable clients (>90) for these specific
			// paths/content-types.
			if reputation > 90 && isGitTraffic(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Deterministic Fast Path: Aho-Corasick & Entropy
			// We check the URI (which includes the query string) plus the two
			// headers most commonly abused to smuggle injection payloads
			// (Referer, User-Agent) for known signatures before entering the heavy
			// WAF engine. These headers frequently land in backend logs/admin views
			// and are classic SQLi/XSS vectors; the signatures are specific enough
			// (e.g. "UNION ", "<script") that legitimate values rarely match.
			if !grpcRequest {
				// We scan the raw RequestURI AND the unescaped version to catch obfuscated attacks.
				rawURI := r.RequestURI
				if fastScanner.Scan(rawURI) {
					match := fastScanner.FindAll(rawURI)
					details := "Request URI match: " + strings.Join(match, ", ")
					recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
					telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_signature").Inc()
					http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
					return
				}

				unescapedURI, _ := url.PathUnescape(rawURI)
				if unescapedURI != "" && unescapedURI != rawURI {
					if fastScanner.Scan(unescapedURI) {
						match := fastScanner.FindAll(unescapedURI)
						details := "Unescaped Request URI match: " + strings.Join(match, ", ")
						recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
						telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_signature").Inc()
						http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
						return
					}
				}

				if referer := r.Header.Get("Referer"); referer != "" && fastScanner.Scan(referer) {
					match := fastScanner.FindAll(referer)
					details := "Referer header match: " + strings.Join(match, ", ")
					recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
					telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_signature").Inc()
					http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
					return
				}
				if ua := r.Header.Get("User-Agent"); ua != "" && fastScanner.Scan(ua) {
					match := fastScanner.FindAll(ua)
					details := "User-Agent header match: " + strings.Join(match, ", ")
					recordFastPathThreat(r, cfg.RouteID, "fast_path_signature", details)
					telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_signature").Inc()
					http.Error(w, "Forbidden by Security Fast-Path (Signature Match)", http.StatusForbidden)
					return
				}
			}

			// Check entropy of common fields to detect shellcode/obfuscation
			if !grpcRequest && !cfg.DisableEntropy {
				threshold := cfg.EntropyThreshold
				if threshold <= 0 {
					threshold = 5.8
				}
				// Adaptive Entropy: If reputation is high, increase threshold to reduce false positives
				if reputation > 90 {
					threshold += 0.5
				} else if reputation < 20 {
					threshold -= 0.5
				}

				for key, vals := range r.Header {
					if isSafeHeader(key) {
						continue
					}
					for _, val := range vals {
						// Increase min length to 64 and threshold to 5.8 to reduce false positives.
						// High entropy in unknown headers is still suspicious.
						if len(val) > 64 && entropy.IsSuspicious(val, threshold) {
							recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", fmt.Sprintf("High entropy in header %s: %.2f (threshold %.2f)", key, entropy.CalculateString(val), threshold))
							telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_entropy").Inc()
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
						telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_fingerprint").Inc()
						http.Error(w, "Forbidden by Security (Client Spoofing Detected)", http.StatusForbidden)
						return
					}

					// H2/H3 Consistency Check
					if (r.ProtoMajor == 2 || r.ProtoMajor == 3) && r.Header.Get("Connection") != "" {
						// Connection header is forbidden in HTTP/2 and HTTP/3
						details := fmt.Sprintf("Protocol violation: %s request from '%s' contains forbidden 'Connection' header", r.Proto, ua)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_protocol_violation", details)
						telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_protocol_violation").Inc()
						http.Error(w, "Forbidden by Security (Protocol Violation)", http.StatusForbidden)
						return
					}

					// Modern browsers always send certain headers
					if r.ProtoMajor >= 2 && r.Header.Get("Accept-Encoding") == "" {
						details := fmt.Sprintf("Suspicious client: %s request from '%s' missing 'Accept-Encoding'", r.Proto, ua)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_suspicious_client", details)
						telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_suspicious_client").Inc()
						http.Error(w, "Forbidden by Security (Suspicious Client)", http.StatusForbidden)
						return
					}
				}
			}

			// 2. Body Entropy Check (Fast-Path)
			if cfg.EnableBodyEntropy && !grpcRequest && r.ContentLength > 0 && r.ContentLength < 1024*1024 {
				peeked, err := peekBody(r, 2048)
				if err == nil && len(peeked) > 64 {
					threshold := cfg.EntropyThreshold
					if threshold <= 0 {
						threshold = 5.8
					}
					// Adaptive Entropy: Content-Type awareness
					ct := strings.ToLower(r.Header.Get("Content-Type"))
					if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "form") {
						threshold += 0.2 // Allow slightly higher entropy for structured data
					}

					if reputation > 90 {
						threshold += 0.5
					} else if reputation < 20 {
						threshold -= 0.5
					}

					if entropy.IsSuspiciousBytes(peeked, threshold) {
						ent := entropy.Calculate(peeked)
						recordFastPathThreat(r, cfg.RouteID, "fast_path_entropy", fmt.Sprintf("High entropy in request body: %.2f (threshold %.2f)", ent, threshold))
						telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_entropy").Inc()
						http.Error(w, "Forbidden by Security Fast-Path (High Body Entropy Detected)", http.StatusForbidden)
						return
					}
				}
			}

			// 3. JWT Fast-Check
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token := auth[7:]
				// JWTs are usually > 32 chars and follow 3-part structure.
				// If it's malformed, it's either an error or an injection attempt.
				if len(token) > 32 && !isJWT(token) {
					recordFastPathThreat(r, cfg.RouteID, "fast_path_malformed_token", "Malformed JWT structure in Authorization header")
					telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(cfg.RouteID, "fast_path_malformed_token").Inc()
					http.Error(w, "Forbidden by Security (Malformed Security Token)", http.StatusForbidden)
					return
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

			wafHandler.ServeHTTP(w, r)
		})
	}, nil
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

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:           typeStr,
		SourceIP:       clientIP,
		Score:          100,
		Details:        details,
		Recommendation: recommendation,
		Time:           time.Now(),
		RouteID:        routeID,
		RequestURI:     r.RequestURI,
		UserAgent:      r.UserAgent(),
		Method:         r.Method,
		Category:       category,
		Severity:       "critical",
		ActionTaken:    "blocked",
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
	coraza.WAF
	routeID string
	cfg     WAFConfig
}

func (w *wafWrapper) NewTransaction() types.Transaction {
	return &txWrapper{
		Transaction: w.WAF.NewTransaction(),
		routeID:     w.routeID,
		cfg:         w.cfg,
	}
}

func (w *wafWrapper) NewTransactionWithID(id string) types.Transaction {
	return &txWrapper{
		Transaction: w.WAF.NewTransactionWithID(id),
		routeID:     w.routeID,
		cfg:         w.cfg,
	}
}

type txWrapper struct {
	types.Transaction
	routeID string
	cfg     WAFConfig
}

func (t *txWrapper) ProcessLogging() {
	if t.IsInterrupted() {
		it := t.Interruption()
		ruleID := strconv.Itoa(it.RuleID)
		telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(t.routeID, ruleID).Inc()
		telemetry.RequestFailuresTotal.WithLabelValues(t.routeID, "waf:"+ruleID).Inc()

		category := "general"
		severity := "medium"
		details := ""
		clientIP := ""
		uri := ""
		isCritical := false

		for _, rule := range t.MatchedRules() {
			if clientIP == "" {
				clientIP = rule.ClientIPAddress()
			}
			if uri == "" {
				uri = rule.URI()
			}
			if rule.Rule().Severity() <= types.RuleSeverityCritical {
				isCritical = true
			}

			// Always check all tags to find the best category
			for _, tag := range rule.Rule().Tags() {
				if strings.Contains(tag, "sqli") {
					category = "sqli"
				} else if strings.Contains(tag, "xss") {
					category = "xss"
				} else if strings.Contains(tag, "rce") || strings.Contains(tag, "php") || strings.Contains(tag, "injection") {
					category = "rce"
				} else if strings.Contains(tag, "lfi") {
					category = "lfi"
				} else if strings.Contains(tag, "scanner") || strings.Contains(tag, "bot") {
					category = "bot"
				} else if strings.Contains(tag, "protocol") {
					category = "protocol"
				} else if strings.Contains(tag, "wordpress") || strings.Contains(tag, "wp_scan") {
					category = "wp_scan"
				}
			}

			if rule.Rule().ID() == it.RuleID {
				severity = strings.ToLower(rule.Rule().Severity().String())
				details = rule.ErrorLog()
			}
		}

		if details == "" && len(t.MatchedRules()) > 0 {
			// Fallback to last matched rule if the interrupting one isn't in matched rules
			// (sometimes happens with evaluation rules)
			last := t.MatchedRules()[len(t.MatchedRules())-1]
			details = last.ErrorLog()
			if clientIP == "" {
				clientIP = last.ClientIPAddress()
			}
			if uri == "" {
				uri = last.URI()
			}
		}

		if clientIP != "" {
			telemetry.GetAggregator().RecordWAFBlock(clientIP)

			// IPS feature: automatically shun IPs at L3/L4 via eBPF.
			// Heuristic: Shun only if it's a critical attack AND (reputation is low OR score is very high).
			// This prevents a single false-positive on a JWT/header from shunning a whole office IP.
			if t.cfg.EbpfManager != nil && isCritical {
				repScore := 100.0
				anomalyScore := 0

				if ca, ok := t.Transaction.(interface {
					GetCollection(variables.RuleVariable) collection.Collection
				}); ok {
					if c, ok := ca.GetCollection(variables.RequestHeaders).(collection.Keyed); ok {
						if vals := c.Get("X-Gateon-Reputation"); len(vals) > 0 {
							if f, err := strconv.ParseFloat(vals[0], 64); err == nil {
								repScore = f
							}
						}
					}
					if c, ok := ca.GetCollection(variables.TX).(collection.Keyed); ok {
						if vals := c.Get("inbound_anomaly_score"); len(vals) > 0 {
							if s, err := strconv.Atoi(vals[0]); err == nil {
								anomalyScore = s
							}
						}
					}
				}

				// Shun conditions:
				// 1. Critical attack from a low-reputation client (rep < 50)
				// 2. High-confidence attack (score >= 20) regardless of reputation
				// 3. Known honeypot/trap hit (ids in 100000 range)
				// 4. Custom critical rules when CRS is disabled
				shouldShun := repScore < 50 || anomalyScore >= 20 || !t.cfg.UseCRS
				if !shouldShun {
					for _, rule := range t.MatchedRules() {
						id := rule.Rule().ID()
						if id >= 100001 && id <= 100013 {
							shouldShun = true
							break
						}
					}
				}

				if shouldShun {
					_ = t.cfg.EbpfManager.ShunIP(clientIP)
				}
			}
		}

		// Record security threat for telemetry and UI
		// We use ActionTaken: "blocked" which will be picked up by the Mitigated Attacks page.
		// We can't easily use RecordSecurityThreatWithJA4 here because we don't have the original *http.Request easily accessible
		// in txhttp.WrapHandler callback, BUT txWrapper has access to the transaction which might have it.
		// Actually, txhttp.WrapHandler usually puts the transaction in context.
		// However, t.cfg has EbpfManager, and t.Transaction has JA4 in its collections if Coraza is configured to extract it.
		// For now, since JA4 is calculated from the request, and we are in ProcessLogging which is phase 5,
		// we should ensure JA4 is passed down.

		ja4 := ""
		ua := ""
		method := ""
		repScore := 100.0
		anomalyScore := 0

		if ca, ok := t.Transaction.(interface {
			GetCollection(variables.RuleVariable) collection.Collection
		}); ok {
			if c, ok := ca.GetCollection(variables.RequestHeaders).(collection.Keyed); ok {
				if vals := c.Get("X-Gateon-JA4"); len(vals) > 0 {
					ja4 = vals[0]
				}
				if vals := c.Get("User-Agent"); len(vals) > 0 {
					ua = vals[0]
				}
				if vals := c.Get("X-Gateon-Reputation"); len(vals) > 0 {
					if f, err := strconv.ParseFloat(vals[0], 64); err == nil {
						repScore = f
					}
				}
			}
			if c, ok := ca.GetCollection(variables.RequestMethod).(collection.Single); ok {
				method = c.Get()
			}
			if c, ok := ca.GetCollection(variables.TX).(collection.Keyed); ok {
				if vals := c.Get("inbound_anomaly_score"); len(vals) > 0 {
					if s, err := strconv.Atoi(vals[0]); err == nil {
						anomalyScore = s
					}
				}
			}
		}

		explanation, recommendation, triggeredRules := generateSmartInsight(t.Transaction, it)

		confidence := 0.8 // Default high confidence for WAF blocks
		ent := 0.0
		if len(t.MatchedRules()) > 0 {
			for _, mr := range t.MatchedRules() {
				for _, md := range mr.MatchedDatas() {
					if v := md.Value(); len(v) > 0 {
						e := entropy.CalculateString(v)
						if e > ent {
							ent = e
						}
					}
				}
			}
		}

		if t.cfg.EnableConfidenceScoring {
			confidence = calculateConfidence(repScore, severity, anomalyScore, false)
		}

		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			ID:             fmt.Sprintf("waf-block-%s", t.ID()),
			Type:           "waf_block",
			SourceIP:       clientIP,
			Score:          100, // Explicit block is a high priority threat
			Details:        explanation,
			Recommendation: recommendation,
			Time:           time.Now(),
			RouteID:        t.routeID,
			RequestURI:     uri,
			Category:       category,
			Severity:       severity,
			ActionTaken:    "blocked",
			JA4:            ja4,
			UserAgent:      ua,
			Method:         method,
			Confidence:     confidence,
			Entropy:        ent,
			TriggeredRules: triggeredRules,
		})
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
