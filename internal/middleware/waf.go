package middleware

import (
	"cmp"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	EnableResponseInspection bool
	AnomalyThreshold         int
	EntropyThreshold         float64 // Threshold for Shannon entropy check (default 5.8)
	DisableEntropy           bool    // If true, skip fast-path entropy check
	RequestBodyLimit         int     // Maximum request body size in bytes
	ResponseBodyLimit        int     // Maximum response body size in bytes
	AuditLogPath             string  // Path to audit log file
	AuditLogRelevantOnly     bool    // Only log relevant transactions
	EbpfManager              ebpf.Manager
	Reputation               *reputation.IPReputationStore
	AllowedAdminIps          []string // IPs allowed to access WP admin
	RulesPath                string   // Path to external WAF rules (CRS)

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
const grpcCompatDirective = `SecAction "id:900200,phase:1,nolog,pass,t:none,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/grpc| |application/grpc+proto| |application/grpc+json| |application/grpc-web| |application/grpc-web+proto| |application/grpc-web+json| |application/grpc-web-text| |application/grpc-web-text+proto|'"
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/grpc" "id:900201,phase:1,nolog,pass,t:lowercase,ctl:ruleRemoveById=920180,ctl:requestBodyAccess=Off"
`

// isGRPCRequest reports whether the request carries a gRPC or gRPC-Web payload.
// gRPC frames are binary protobuf with high Shannon entropy and binary "-bin"
// metadata headers; the deterministic byte/entropy fast-paths would false-positive
// on that framing, so they are skipped for gRPC traffic. The CRS engine still
// inspects gRPC request headers and the URI.
func isGRPCRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

const securityExclusionsDirective = `
# CRS Exclusions for sensitive high-entropy headers (JWTs, API Keys)
# These rules often false-positive on long base64 strings or crypt hashes.
SecRuleUpdateTargetById 942100 "!REQUEST_HEADERS:Authorization"
SecRuleUpdateTargetById 942100 "!REQUEST_HEADERS:X-Api-Key"
SecRuleUpdateTargetById 942200 "!REQUEST_HEADERS:Authorization"
SecRuleUpdateTargetById 942200 "!REQUEST_HEADERS:X-Api-Key"
SecRuleUpdateTargetById 942260 "!REQUEST_HEADERS:Authorization"
SecRuleUpdateTargetById 942260 "!REQUEST_HEADERS:X-Api-Key"
SecRuleUpdateTargetById 941100 "!REQUEST_HEADERS:Authorization"
SecRuleUpdateTargetById 941100 "!REQUEST_HEADERS:X-Api-Key"

# Redact sensitive headers from Coraza audit log
SecAction "id:900300,phase:1,nolog,pass,setvar:tx.redact_headers=Authorization,setvar:tx.redact_headers=X-Api-Key,setvar:tx.redact_headers=Cookie,setvar:tx.redact_headers=Set-Cookie"
`

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

		// Adaptive WAF: Adjust anomaly thresholds based on Gateon Reputation.
		// Trustworthy clients (Reputation > 90) are given more room for high-entropy headers (JWTs).
		// Unknown or low reputation clients are subject to strict enforcement.
		// Rules are ordered progressively so the most specific match (highest reputation) wins.
		sb.WriteString(`
# Adaptive Anomaly Thresholds (Progressive Override)
SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 0"  "id:900001,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=2"
SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 15" "id:900012,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=3"
SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 40" "id:900013,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=4"
SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 80" "id:900011,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"
SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 95" "id:900010,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"
`)

		sb.WriteString("Include @owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf\n")

		// gRPC compatibility: REQUEST-901-INITIALIZATION sets a default
		// tx.allowed_request_content_type list that does NOT include the gRPC
		// content types, so REQUEST-920 Protocol Enforcement rule 920420
		// ("Request content type is not allowed by policy") adds a critical
		// anomaly score for every gRPC / gRPC-Web request. With the default
		// inbound anomaly threshold of 5 that single hit trips
		// REQUEST-949-BLOCKING-EVALUATION -> 403. We extend the allow-list with
		// the gRPC family before 920 is included (phase:1 directives run in load
		// order, so this overrides the 901 default before 920420 evaluates).
		// This keeps full CRS coverage for gRPC headers/URI while letting the
		// legitimate gRPC transport through. See grpcCompatDirective for details.
		// Only emitted for routes the operator typed as gRPC — never on HTTP/
		// GraphQL routes — so it cannot be used to weaken their inspection.
		if cfg.GRPCMode {
			sb.WriteString(grpcCompatDirective)
		}

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
			sb.WriteString("SecRule REQUEST_HEADERS:X-Gateon-IP-Reputation-Block \"@eq 1\" \"id:910000,phase:1,nolog,pass,setvar:tx.ip_reputation_block_flag=1\"\n")
			// REQUEST-910-IP-REPUTATION.conf is missing in some CRS 4.0 distributions.
			// We provide a basic rule that blocks based on the ip_reputation_block_flag.
			// We use phase:2 to ensure it catches variables set in phase:1 directives.
			sb.WriteString("SecRule TX:ip_reputation_block_flag \"@eq 1\" \"id:910001,phase:2,deny,status:403,msg:'IP Reputation block',tag:'reputation',severity:CRITICAL\"\n")
		}
		if cfg.EnableDOSProtection {
			sb.WriteString(`SecAction "id:900002,phase:1,nolog,pass,setvar:tx.dos_burst_time_slice=60,setvar:tx.dos_counter_threshold=100,setvar:tx.dos_block_timeout=600"
`)
			// REQUEST-912-DOS-PROTECTION.conf is missing in some CRS 4.0 distributions
			// sb.WriteString("Include @owasp_crs/REQUEST-912-DOS-PROTECTION.conf\n")
		}

		// WP Scanning and Exploits
		if !cfg.DisableWordPress {
			// Basic WP protection rules if CRS doesn't have them enabled by default
			allowedIps := "127.0.0.1"
			if len(cfg.AllowedAdminIps) > 0 {
				allowedIps = strings.Join(append([]string{"127.0.0.1"}, cfg.AllowedAdminIps...), " ")
			}

			sb.WriteString(fmt.Sprintf(`
SecRule REQUEST_URI "@contains /wp-admin" "id:100001,phase:1,deny,status:403,msg:'WordPress admin access attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %s"
SecRule REQUEST_URI "@contains /wp-login.php" "id:100002,phase:1,deny,status:403,msg:'WordPress login attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %s"
SecRule REQUEST_URI "@rx /wp-content/plugins/.*\.php" "id:100003,phase:1,deny,status:403,msg:'WordPress plugin execution attempt',tag:'wp_scan',severity:CRITICAL"
`, allowedIps, allowedIps))
		}

		// Malware and File Upload protection
		if cfg.EnableMalwareDetection {
			sb.WriteString(`
SecRule FILES_NAMES "@rx \.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$" \
    "id:100004,phase:2,deny,status:403,msg:'Suspicious file upload extension',tag:'malware',severity:CRITICAL"
SecRule FILES "@contains <?php" \
    "id:100005,phase:2,deny,status:403,msg:'PHP code injection in file upload',tag:'malware',severity:CRITICAL"
SecRule FILES "@rx %PDF-1\.[0-7].*obj.*<<.*\/JS.*>>.*endobj" \
    "id:100006,phase:2,deny,status:403,msg:'PDF with JavaScript detected',tag:'malware',severity:CRITICAL"
`)
		}

		// Additional protections for Golang and Java
		sb.WriteString(`
# Golang specific injection patterns
SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (os/exec|net/http/httputil|reflect\.ValueOf|unsafe\.Pointer|go\s+func\()" \
    "id:100010,phase:2,deny,status:403,msg:'Potential Golang code injection',tag:'rce',tag:'golang',severity:CRITICAL"

# Java specific injection patterns (supplemental to CRS)
SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (runtime\.exec|java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.crypto|javax\.script|ognl\.|java\.net\.URLClassLoader)" \
    "id:100011,phase:2,deny,status:403,msg:'Potential Java code injection',tag:'rce',tag:'java',severity:CRITICAL"

# Java/Log4j protection
SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx \$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):" \
    "id:100013,phase:2,deny,status:403,msg:'Potential Log4Shell (CVE-2021-44228) attempt',tag:'rce',tag:'java',severity:CRITICAL"

# WordPress additional scan protection
SecRule REQUEST_URI "@rx (wp-json/wp/v2/users|wp-links-opml\.php|wp-config-sample\.php|wp-content/debug\.log|readme\.html|license\.txt|wp-content/uploads/.*\.php)" \
    "id:100012,phase:1,deny,status:403,msg:'WordPress enumeration/info leak attempt',tag:'wp_scan',severity:CRITICAL"
`)

		// Ransomware protection
		if cfg.EnableRansomwareDetection {
			sb.WriteString(`
SecRule FILES_NAMES "@rx \.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$" \
    "id:100007,phase:2,deny,status:403,msg:'Ransomware file extension detected',tag:'ransomware',severity:CRITICAL"
`)
		}
		sb.WriteString(securityExclusionsDirective)

		// Blocking evaluation
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

	if cfg.RequestBodyLimit > 0 {
		wafConfig = wafConfig.WithRequestBodyLimit(cfg.RequestBodyLimit)
		// Also set in-memory limit to 10% of total limit or 1MB min, but not exceeding the total limit
		memLimit := int64(cfg.RequestBodyLimit) / 10
		if memLimit < 1024*1024 {
			memLimit = 1024 * 1024
		}
		memLimit = min(memLimit, int64(cfg.RequestBodyLimit))
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
			// Security Header Spoofing Prevention: clear internal headers from incoming request.
			r.Header.Del("X-Gateon-Reputation")
			r.Header.Del("X-Gateon-Anomaly-Score")
			r.Header.Del("X-Gateon-Threat-Type")
			r.Header.Del("X-Gateon-WAF-Matched")

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
	if strings.Contains(lowerDetails, "sql") || strings.Contains(lowerDetails, "union") {
		category = "sqli"
	} else if strings.Contains(lowerDetails, "script") || strings.Contains(lowerDetails, "xss") {
		category = "xss"
	} else if strings.Contains(lowerDetails, "scanner") || strings.Contains(lowerDetails, "nmap") || strings.Contains(lowerDetails, "sqlmap") {
		category = "bot"
	}

	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
		Type:        typeStr,
		SourceIP:    clientIP,
		Score:       100,
		Details:     details,
		Time:        time.Now(),
		RouteID:     routeID,
		RequestURI:  r.RequestURI,
		UserAgent:   r.UserAgent(),
		Method:      r.Method,
		Category:    category,
		Severity:    "critical",
		ActionTaken: "blocked",
	})
}

func isSafeHeader(name string) bool {
	// Fast path for canonical headers (most frequent in modern browsers)
	switch name {
	case "Authorization", "Cookie", "Set-Cookie", "X-Csrf-Token", "X-Xsrf-Token",
		"Sec-Websocket-Key", "Sec-Websocket-Accept", "X-Api-Key", "X-Auth-Token",
		"X-Gateon-Fingerprint", "X-Request-Id", "X-Correlation-Id",
		"X-Amz-Date", "X-Amz-Security-Token":
		return true
	}

	// Prefix checks without allocation
	if hasPrefixFold(name, "X-Amz-") ||
		hasPrefixFold(name, "X-Goog-") ||
		hasPrefixFold(name, "X-Apple-") ||
		hasPrefixFold(name, "X-Ms-") ||
		hasPrefixFold(name, "Grpc-") {
		return true
	}

	// Fallback for non-canonical forms
	if strings.EqualFold(name, "authorization") || strings.EqualFold(name, "cookie") {
		return true
	}

	return false
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
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			ID:          fmt.Sprintf("waf-block-%s", t.ID()),
			Type:        "waf_block",
			SourceIP:    clientIP,
			Score:       100, // Explicit block is a high priority threat
			Details:     fmt.Sprintf("WAF blocked request (Rule %s): %s", ruleID, details),
			Time:        time.Now(),
			RouteID:     t.routeID,
			RequestURI:  uri,
			Category:    category,
			Severity:    severity,
			ActionTaken: "blocked",
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
		UseCRS:                    useCRS,
		ParanoiaLevel:             pl,
		Directives:                strings.TrimSpace(cfg["directives"]),
		DirectivesFile:            strings.TrimSpace(cfg["directives_file"]),
		TrustCloudflare:           request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
		AuditOnly:                 auditOnly,
		DisableSQLI:               isFalse("sqli"),
		DisableXSS:                isFalse("xss"),
		DisableLFI:                isFalse("lfi"),
		DisableRCE:                isFalse("rce"),
		DisablePHP:                isFalse("php"),
		DisableScanner:            isFalse("scanner"),
		DisableProtocol:           isFalse("protocol"),
		DisableJava:               isFalse("java"),
		DisableNodeJS:             isFalse("nodejs"),
		DisableWordPress:          isFalse("wordpress"),
		EnableIPReputation:        strings.TrimSpace(strings.ToLower(cfg["ip_reputation"])) == "true",
		EnableDOSProtection:       strings.TrimSpace(strings.ToLower(cfg["dos_protection"])) == "true",
		EnableMalwareDetection:    strings.TrimSpace(strings.ToLower(cfg["malware_detection"])) == "true",
		EnableRansomwareDetection: strings.TrimSpace(strings.ToLower(cfg["ransomware_detection"])) == "true",
		EnableDLP:                 strings.TrimSpace(strings.ToLower(cfg["dlp"])) == "true",
		AnomalyThreshold:          anomalyThreshold,
		EntropyThreshold:          entropyThreshold,
		DisableEntropy:            disableEntropy,
		RequestBodyLimit:          intVal(cfg["request_body_limit"]),
		ResponseBodyLimit:         intVal(cfg["response_body_limit"]),
		AuditLogPath:              strings.TrimSpace(cfg["audit_log_path"]),
		AuditLogRelevantOnly:      strings.TrimSpace(strings.ToLower(cfg["audit_log_relevant_only"])) != "false",
		RouteID:                   routeID,
		AllowedAdminIps:           allowedAdminIps,
		RulesPath:                 strings.TrimSpace(cfg["rules_path"]),
	}
}

func intVal(v string) int {
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}
