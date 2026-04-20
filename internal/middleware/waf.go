package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
)

// WAFConfig configures the WAF middleware.
type WAFConfig struct {
	UseCRS           bool   // Use OWASP CRS (default true)
	ParanoiaLevel    int    // CRS paranoia level 1-4 (default 1)
	DirectivesFile   string // Optional path to custom directives file
	TrustCloudflare  bool   // Use CF-Connecting-IP for REMOTE_ADDR in request
	AuditOnly        bool   // If true, log matches but do not block (SecRuleEngine DetectionOnly)
	GlobalDirectives string // Combined global rules from GlobalConfig
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
		directives := fmt.Sprintf(`%sSecAction "id:900000,phase:1,nolog,pass,setvar:tx.paranoia_level=%d"
Include @owasp_crs/crs-setup.conf
Include @owasp_crs/rules/*.conf
`, engineDirective, pl)
		wafConfig = wafConfig.
			WithDirectives(directives).
			WithRootFS(coreruleset.FS)
	}

	if cfg.GlobalDirectives != "" {
		wafConfig = wafConfig.WithDirectives(cfg.GlobalDirectives)
	}

	if cfg.DirectivesFile != "" {
		wafConfig = wafConfig.WithDirectivesFromFile(cfg.DirectivesFile)
	} else if !cfg.UseCRS {
		// Minimal pass-through when neither CRS nor custom file
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

	return func(next http.Handler) http.Handler {
		wafHandler := txhttp.WrapHandler(waf, next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	return WAFConfig{
		UseCRS:          useCRS,
		ParanoiaLevel:   pl,
		DirectivesFile:  strings.TrimSpace(cfg["directives_file"]),
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
		AuditOnly:       auditOnly,
	}
}
