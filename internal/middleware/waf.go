package middleware

import (
	"cmp"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
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
	AnomalyThreshold          int
	RequestBodyLimit          int    // Maximum request body size in bytes
	ResponseBodyLimit         int    // Maximum response body size in bytes
	AuditLogPath              string // Path to audit log file
	AuditLogRelevantOnly      bool   // Only log relevant transactions
	EbpfManager               ebpf.Manager
	AllowedAdminIps           []string // IPs allowed to access WP admin
	RulesPath                 string   // Path to external WAF rules (CRS)
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
		engineDirective := ""
		if cfg.AuditOnly {
			engineDirective = `SecRuleEngine DetectionOnly
`
		}

		sb.WriteString(engineDirective)
		_, _ = fmt.Fprintf(&sb, `SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d"
Include @crs-setup.conf.example
`, pl)

		if cfg.AnomalyThreshold > 0 {
			_, _ = fmt.Fprintf(&sb, `SecAction "id:900001,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
`, cfg.AnomalyThreshold, cfg.AnomalyThreshold)
		}

		// Basic enforcement and common rules
		sb.WriteString("Include @owasp_crs/REQUEST-901-INITIALIZATION.conf\n")
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
			// In CRS 4.0, NodeJS attacks are covered by the Generic Attacks ruleset
			sb.WriteString("Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf\n")
		}
		if cfg.EnableIPReputation {
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

		// Ransomware protection
		if cfg.EnableRansomwareDetection {
			sb.WriteString(`
SecRule FILES_NAMES "@rx \.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$" \
    "id:100007,phase:2,deny,status:403,msg:'Ransomware file extension detected',tag:'ransomware',severity:CRITICAL"
`)
		}

		// Blocking evaluation
		sb.WriteString("Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf\n")

		// Response rules
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
		sb.WriteString("Include @owasp_crs/RESPONSE-980-CORRELATION.conf\n")

		if cfg.RulesPath != "" {
			wafConfig = wafConfig.WithRootFS(os.DirFS(cfg.RulesPath))
		} else {
			wafConfig = wafConfig.WithRootFS(fsWrapper{coreruleset.FS})
		}
	}

	if cfg.AuditLogPath != "" {
		auditEngine := "On"
		if cfg.AuditLogRelevantOnly {
			auditEngine = "RelevantOnly"
		}
		_, _ = fmt.Fprintf(&sb, `
SecAuditEngine %s
SecAuditLogParts ABIJDEFHKZ
SecAuditLogType Serial
SecAuditLog "%s"
`, auditEngine, strings.ReplaceAll(cfg.AuditLogPath, "\\", "/"))
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
	if cfg.ResponseBodyLimit > 0 {
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

		// IPS feature: automatically shun IPs that trigger critical security rules
		if mr.Rule().Severity() <= types.RuleSeverityCritical && cfg.EbpfManager != nil {
			_ = cfg.EbpfManager.ShunIP(mr.ClientIPAddress())
		}

		severity := strings.ToLower(mr.Rule().Severity().String())
		category := "general"
		for _, tag := range mr.Rule().Tags() {
			if strings.Contains(tag, "sqli") {
				category = "sqli"
			} else if strings.Contains(tag, "xss") {
				category = "xss"
			} else if strings.Contains(tag, "rce") {
				category = "rce"
			} else if strings.Contains(tag, "lfi") {
				category = "lfi"
			} else if strings.Contains(tag, "scanner") {
				category = "bot"
			} else if strings.Contains(tag, "protocol") {
				category = "protocol"
			}
		}

		// Record security threat for telemetry and UI
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			ID:          fmt.Sprintf("waf-%d-%s", mr.Rule().ID(), mr.TransactionID()),
			Type:        "waf_block",
			SourceIP:    mr.ClientIPAddress(),
			Score:       float64(100 - (int(mr.Rule().Severity()) * 10)),
			Details:     fmt.Sprintf("WAF Rule %s: %s", ruleID, mr.ErrorLog()),
			Time:        time.Now(),
			RouteID:     cfg.RouteID,
			RequestURI:  mr.URI(),
			Category:    category,
			Severity:    severity,
			ActionTaken: "blocked",
		})
	})

	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("create WAF: %w", err)
	}

	wrappedWaf := &wafWrapper{WAF: waf, routeID: cfg.RouteID}

	return func(next http.Handler) http.Handler {
		wafHandler := txhttp.WrapHandler(wrappedWaf, next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.TrustCloudflare {
				r.RemoteAddr = request.GetClientIP(r, true)
			}
			// We can't easily pass routeID to ErrorCallback because it's set at WAF creation.
			// But we can record it here if we use a different approach.
			// For now, let's at least skip the whole WAF for internal traffic if ShouldSkipMetrics is true.
			wafHandler.ServeHTTP(w, r)
		})
	}, nil
}

type wafWrapper struct {
	coraza.WAF
	routeID string
}

func (w *wafWrapper) NewTransaction() types.Transaction {
	return &txWrapper{
		Transaction: w.WAF.NewTransaction(),
		routeID:     w.routeID,
	}
}

func (w *wafWrapper) NewTransactionWithID(id string) types.Transaction {
	return &txWrapper{
		Transaction: w.WAF.NewTransactionWithID(id),
		routeID:     w.routeID,
	}
}

type txWrapper struct {
	types.Transaction
	routeID string
}

func (t *txWrapper) Close() error {
	if t.IsInterrupted() {
		it := t.Interruption()
		ruleID := strconv.Itoa(it.RuleID)
		telemetry.MiddlewareWAFBlockedTotal.WithLabelValues(t.routeID, ruleID).Inc()
		telemetry.RequestFailuresTotal.WithLabelValues(t.routeID, "waf:"+ruleID).Inc()

		// Record granular mitigated threat metrics
		category := "unknown"
		severity := "unknown"
		for _, rule := range t.MatchedRules() {
			if rule.Rule().ID() == it.RuleID {
				severity = strings.ToLower(rule.Rule().Severity().String())
				for _, tag := range rule.Rule().Tags() {
					if strings.Contains(tag, "sqli") {
						category = "sqli"
					} else if strings.Contains(tag, "xss") {
						category = "xss"
					} else if strings.Contains(tag, "rce") {
						category = "rce"
					} else if strings.Contains(tag, "lfi") {
						category = "lfi"
					} else if strings.Contains(tag, "scanner") {
						category = "bot"
					} else if strings.Contains(tag, "wordpress") || strings.Contains(tag, "wp_scan") {
						category = "wp_scan"
					}
				}
				break
			}
		}
		telemetry.MitigatedThreatsTotal.WithLabelValues(category, severity, "blocked").Inc()
	}
	return t.Transaction.Close()
}

// fsWrapper wraps an fs.FS to convert backslashes to forward slashes,
// which is required for embed.FS to work correctly on Windows.
type fsWrapper struct {
	fs.FS
}

func (f fsWrapper) Open(name string) (fs.File, error) {
	return f.FS.Open(strings.ReplaceAll(name, "\\", "/"))
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
		AnomalyThreshold:          intVal(cfg["anomaly_threshold"]),
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
