package middleware

import (
	"cmp"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
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
	DisableSQLI     bool
	DisableXSS      bool
	DisableLFI      bool
	DisableRCE      bool
	DisablePHP      bool
	DisableScanner  bool
	DisableProtocol bool
	DisableJava     bool
}

// WAF returns a middleware that applies OWASP Coraza WAF with optional CRS.
func WAF(cfg WAFConfig) (Middleware, error) {
	wafConfig := coraza.NewWAFConfig()

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

		var sb strings.Builder
		sb.WriteString(engineDirective)
		_, _ = fmt.Fprintf(&sb, `SecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d"
Include @crs-setup.conf.example
`, pl)

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

		// Blocking evaluation
		sb.WriteString("Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf\n")

		// Response rules
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

		wafConfig = wafConfig.
			WithRootFS(fsWrapper{coreruleset.FS}).
			WithDirectives(sb.String())
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

	wafConfig = wafConfig.WithErrorCallback(func(mr types.MatchedRule) {
		ruleID := strconv.Itoa(mr.Rule().ID())
		logger.L.Warn().
			Str("rule_id", ruleID).
			Str("message", mr.ErrorLog()).
			Msg("WAF matched rule")
		// Note: ErrorCallback doesn't have access to *http.Request directly here in Coraza v3
		// but we can check it in the middleware itself if we want to skip metrics.
		// However, most WAF matches will be recorded unless we wrap them.
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

	return WAFConfig{
		UseCRS:          useCRS,
		ParanoiaLevel:   pl,
		Directives:      strings.TrimSpace(cfg["directives"]),
		DirectivesFile:  strings.TrimSpace(cfg["directives_file"]),
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
		AuditOnly:       auditOnly,
		DisableSQLI:     isFalse("sqli"),
		DisableXSS:      isFalse("xss"),
		DisableLFI:      isFalse("lfi"),
		DisableRCE:      isFalse("rce"),
		DisablePHP:      isFalse("php"),
		DisableScanner:  isFalse("scanner"),
		DisableProtocol: isFalse("protocol"),
		DisableJava:     isFalse("java"),
		RouteID:         routeID,
	}
}
