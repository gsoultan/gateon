// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// resolveWAFTier returns the WAF inspection tier: the explicit WafConfig.tier
// when set, otherwise the WAF tier implied by the active global profile.
func resolveWAFTier(w *gateonv1.WafConfig) config.Tier {
	if t := strings.TrimSpace(w.GetTier()); t != "" {
		return config.NormalizeTier(t)
	}
	return config.CurrentTierDefaults().WAFTier
}

// applyWAFTier sets the tier baseline on cfg. Precedence is: tier sets the
// baseline; callers may then honour explicit proto "enable" flags to add (never
// remove) protection. minimal = protocol+SQLi+XSS at PL1, request-phase only;
// standard = full request-phase CRS; enterprise = PL>=2 plus the response-phase
// (DLP) rules and malware/ransomware detection.
func applyWAFTier(cfg *WAFConfig, tier config.Tier) {
	switch tier {
	case config.TierMinimal:
		cfg.ParanoiaLevel = 1
		cfg.DisableLFI = true
		cfg.DisableRCE = true
		cfg.DisablePHP = true
		cfg.DisableJava = true
		cfg.DisableNodeJS = true
		cfg.DisableScanner = true
		cfg.EnableMalwareDetection = false
		cfg.EnableRansomwareDetection = false
		cfg.EnableDLP = false
		cfg.EnableResponseInspection = false
	case config.TierEnterprise:
		if cfg.ParanoiaLevel < 2 {
			cfg.ParanoiaLevel = 2
		}
		cfg.EnableMalwareDetection = true
		cfg.EnableRansomwareDetection = true
		cfg.EnableDLP = true
		cfg.EnableResponseInspection = true
	default: // standard: full request-phase coverage, response phase off by default
		cfg.EnableResponseInspection = false
	}
}

var wafCache sync.Map

// globalWAFCache memoizes the global WAF middleware keyed by the global WAF
// config bytes, so it is compiled once and shared by every route rather than
// rebuilt per route in ApplyRouteMiddlewares.
var globalWAFCache sync.Map

// CreateGlobalWAF builds the gateway-wide WAF middleware from the global config.
//
// It returns (nil, nil) when global WAF is disabled. Unlike the per-route
// createWAF path, it does NOT merge the proto's positive category booleans into
// the cfg map — that legacy merge writes "false" for every unset category, which
// the parser maps to Disable*=true and silently strips the entire OWASP CRS
// attack coverage (the root cause of "WAF detections = 0" once enabled). Instead
// it enables the full CRS attack set plus malware/ransomware detection by
// default, keeping only the false-positive-prone rule groups (WordPress admin
// lockdown) opt-in via the proto flags.
func NewGlobalWAF(d security.Deps) (kind.Middleware, error) {
	if d.GlobalStore == nil {
		return nil, nil
	}
	g := d.GlobalStore.Get(context.TODO())
	if g == nil || g.Waf == nil || !g.Waf.GetEnabled() {
		return nil, nil
	}
	w := g.Waf

	// gRPC relaxations are keyed on the trusted route type, so the gateway-wide
	// WAF is memoized as two distinct variants (strict vs gRPC-relaxed). An HTTP
	// route never receives the gRPC-relaxed instance, so a spoofed Content-Type
	// cannot disable its body inspection.
	grpcMode := d.IsGRPCRoute()
	// The resolved tier may come from the global profile (env/config), which is
	// not part of the WAF proto, so it must be in the cache key alongside the
	// proto hash and the gRPC variant.
	tier := resolveWAFTier(w)
	key := "global-waf:" + string(tier) + ":" + strconv.FormatBool(grpcMode) + ":" + hashWAFProto(w)
	if cached, ok := globalWAFCache.Load(key); ok {
		return cached.(kind.Middleware), nil
	}

	logger.L.LogInfo("Creating Global WAF middleware")
	cfg := globalWAFConfig(w, tier, d)

	mw, err := WAF(cfg)
	if err != nil {
		return nil, err
	}
	globalWAFCache.Store(key, mw)
	return mw, nil
}

// globalWAFConfig turns the gateway-wide WAF proto into an engine config.
// Split out of NewGlobalWAF because the two do unrelated jobs: this one
// translates settings, and the caller decides whether to build at all, what to
// key the cache on, and what to do with the result.
func globalWAFConfig(w *gateonv1.WafConfig, tier config.Tier, d security.Deps) WAFConfig {
	pl := int(w.GetParanoiaLevel())
	if pl < 1 {
		pl = 1
	}

	cfg := WAFConfig{
		ParanoiaLevel: pl,
		// Full OWASP CRS attack coverage stays enabled (Disable*=false).
		// Opt-in, false-positive-prone groups honour the explicit proto flag:
		DisableWordPress: !w.GetWordpress(), // WP admin lockdown breaks legit /wp-admin
		// Robust extras — malware & ransomware on by default for the global WAF:
		EnableMalwareDetection:    true,
		EnableRansomwareDetection: true,
		EnableIPReputation:        w.GetIpReputation(),
		EnableDOSProtection:       w.GetDosProtection(),
		EnableDLP:                 w.GetDlp(),
		// Unset falls through to GATEON_WAF_DLP_ACTION and then to block, so an
		// install that has never heard of this keeps refusing leaks.
		DLPAction:                   parseDLPAction(w.GetDlpAction()),
		AnomalyThreshold:            int(w.GetAnomalyThreshold()),
		RequestBodyLimit:            int(w.GetRequestBodyLimit()),
		ResponseBodyLimit:           int(w.GetResponseBodyLimit()),
		AuditLogPath:                w.GetAuditLogPath(),
		AuditLogRelevantOnly:        w.GetAuditLogRelevantOnly(),
		AllowedAdminIps:             w.GetAllowedAdminIps(),
		EntropyThreshold:            w.GetEntropyThreshold(),
		DisableEntropy:              w.GetDisableEntropy(),
		EnableBodyEntropy:           w.GetEnableBodyEntropy(),
		EnableFingerprintValidation: w.GetEnableFingerprintValidation(),
		EnableConfidenceScoring:     w.GetEnableConfidenceScoring(),
		AuditOnly:                   w.GetAuditOnly(),
		TrustCloudflare:             config.TrustCloudflare(w),
		AppProfiles:                 w.GetAppProfiles(),
		EnableSSRFProtection:        w.GetSsrfProtection(),
		Origins:                     resolveOrigins(w.GetOrigins()),
		RouteID:                     "gateon-global-waf",
		EbpfManager:                 d.EbpfManager,
		Reputation:                  d.Reputation,
		WafRules:                    waf.GetStore(),
	}

	// Apply the resolved tier baseline, then honour an explicit DLP opt-in as an
	// upgrade: a user who deliberately enabled DLP gets response inspection even
	// at the standard tier, while DLP stays off by default below enterprise.
	applyWAFTier(&cfg, tier)
	if w.GetDlp() {
		cfg.EnableDLP = true
		cfg.EnableResponseInspection = true
	}

	// Rules are no longer fetched from disk. gateon's corpus is compiled into
	// the binary and gwaf's core ruleset ships with the engine, so "update the
	// rules" is now "upgrade gateon" — which is also what makes the rules
	// something gateon tests rather than something each install downloads a
	// possibly-different copy of. The auto_update_rules setting is kept on the
	// wire so existing configuration still loads; it no longer does anything.

	return cfg
}

func hashWAFProto(w *gateonv1.WafConfig) string {
	b, err := proto.Marshal(w)
	if err != nil {
		return "nohash"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// setIfMissing writes a global default only where the route did not speak. A
// route that explicitly turned something off must stay off, so every global
// value goes through here rather than through assignment.
func setIfMissing(cfg map[string]string, key, val string) {
	if _, ok := cfg[key]; !ok {
		cfg[key] = val
	}
}

// mergeGlobalWAFDefaults fills unset per-route settings from the gateway-wide
// WAF config and returns its custom directives. Nothing happens unless the
// global WAF is both present and enabled.
func mergeGlobalWAFDefaults(cfg map[string]string, d security.Deps) string {
	if d.GlobalStore == nil {
		return ""
	}
	global := d.GlobalStore.Get(context.TODO())
	if global == nil || global.Waf == nil || !global.Waf.Enabled {
		return ""
	}
	// A route with its own WAF skips the global one (router.go), so response
	// DLP has to be inherited whatever use_crs says, and as the global WAF
	// actually runs it -- its tier baseline included. Taken only with use_crs
	// and only from the raw flag, attaching a WAF to a route switched off the
	// response inspection the global WAF had been giving it.
	setIfMissing(cfg, "dlp", strconv.FormatBool(globalWAFRunsDLP(global.Waf)))
	// Cloudflare trust is a fact about where the gateway sits, not a CRS
	// setting, so it is inherited on the same terms.
	setIfMissing(cfg, "trust_cloudflare_headers", strconv.FormatBool(config.TrustCloudflare(global.Waf)))
	if global.Waf.DlpAction != "" {
		setIfMissing(cfg, "dlp_action", global.Waf.DlpAction)
	}
	if global.Waf.UseCrs {
		applyGlobalCRSDefaults(cfg, global.Waf, d.DataDir)
	}
	return global.Waf.CustomDirectives
}

// globalWAFRunsDLP reports whether NewGlobalWAF inspects responses for data
// leaks: when DLP is switched on, or when the tier's baseline turns it on.
func globalWAFRunsDLP(w *gateonv1.WafConfig) bool {
	return w.GetDlp() || resolveWAFTier(w) == config.TierEnterprise
}

// applyGlobalCRSDefaults copies the gateway-wide ruleset and tuning settings
// into a route's config wherever the route left them unset.
func applyGlobalCRSDefaults(cfg map[string]string, w *gateonv1.WafConfig, dataDir string) {
	applyGlobalCRSToggles(cfg, w)
	applyGlobalCRSTunables(cfg, w, dataDir)
}

// applyGlobalCRSToggles copies the on/off settings, where the proto's zero
// value and "off" are the same thing.
func applyGlobalCRSToggles(cfg map[string]string, w *gateonv1.WafConfig) {
	for key, val := range map[string]bool{
		"sqli":                          w.Sqli,
		"xss":                           w.Xss,
		"lfi":                           w.Lfi,
		"rce":                           w.Rce,
		"php":                           w.Php,
		"scanner":                       w.Scanner,
		"protocol":                      w.Protocol,
		"java":                          w.Java,
		"nodejs":                        w.Nodejs,
		"wordpress":                     w.Wordpress,
		"ip_reputation":                 w.IpReputation,
		"dos_protection":                w.DosProtection,
		"malware_detection":             w.MalwareDetection,
		"ransomware_detection":          w.RansomwareDetection,
		"dlp":                           w.Dlp,
		"audit_log_relevant_only":       w.AuditLogRelevantOnly,
		"disable_entropy":               w.DisableEntropy,
		"enable_body_entropy":           w.EnableBodyEntropy,
		"enable_fingerprint_validation": w.EnableFingerprintValidation,
		"enable_confidence_scoring":     w.EnableConfidenceScoring,
		"audit_only":                    w.AuditOnly,
	} {
		setIfMissing(cfg, key, strconv.FormatBool(val))
	}
}

// applyGlobalCRSTunables copies the settings whose zero value means "not
// configured" rather than "off", so each is copied only when the global
// actually set it. Treating them like the toggles above would push a route's
// body limit to zero because the gateway never named one.
func applyGlobalCRSTunables(cfg map[string]string, w *gateonv1.WafConfig, dataDir string) {
	if w.DlpAction != "" {
		setIfMissing(cfg, "dlp_action", w.DlpAction)
	}
	if w.AnomalyThreshold > 0 {
		setIfMissing(cfg, "anomaly_threshold", strconv.Itoa(int(w.AnomalyThreshold)))
	}
	if w.RequestBodyLimit > 0 {
		setIfMissing(cfg, "request_body_limit", strconv.Itoa(int(w.RequestBodyLimit)))
	}
	if w.ResponseBodyLimit > 0 {
		setIfMissing(cfg, "response_body_limit", strconv.Itoa(int(w.ResponseBodyLimit)))
	}
	if w.AuditLogPath != "" {
		setIfMissing(cfg, "audit_log_path", w.AuditLogPath)
	}
	if len(w.AllowedAdminIps) > 0 {
		setIfMissing(cfg, "allowed_admin_ips", strings.Join(w.AllowedAdminIps, ","))
	}
	if w.EntropyThreshold > 0 {
		setIfMissing(cfg, "entropy_threshold", strconv.FormatFloat(w.EntropyThreshold, 'f', -1, 64))
	}

	// auto_update_rules no longer downloads anything, but an install that
	// already has a rules directory on disk keeps using it.
	if w.AutoUpdateRules {
		rulesPath := filepath.Join(dataDir, "waf", "rules")
		if _, err := os.Stat(rulesPath); err == nil {
			cfg["rules_path"] = rulesPath
		}
	}
}

func NewWAF(cfg map[string]string, d security.Deps) (kind.Middleware, error) {
	globalDirectives := mergeGlobalWAFDefaults(cfg, d)

	grpcMode := d.IsGRPCRoute()
	key := wafConfigKey(cfg) + ":" + globalDirectives + ":grpc=" + strconv.FormatBool(grpcMode)
	if cached, ok := wafCache.Load(key); ok {
		return cached.(kind.Middleware), nil
	}
	wafCfg := parseWAFConfig(cfg)
	warnUnexecutableDirectives(globalDirectives, wafCfg.RouteID)
	wafCfg.EbpfManager = d.EbpfManager
	wafCfg.Reputation = d.Reputation
	wafCfg.WafRules = waf.GetStore()

	mw, err := WAF(wafCfg)
	if err != nil {
		return nil, err
	}
	wafCache.Store(key, mw)
	return mw, nil
}

// InvalidateWAFCache clears all cached WAF instances and middlewares.
// Call when a WAF configuration or rule is saved or deleted.
func InvalidateWAFCache() {
	wafCache.Range(func(key, _ any) bool {
		wafCache.Delete(key)
		return true
	})
	globalWAFCache.Range(func(key, _ any) bool {
		globalWAFCache.Delete(key)
		return true
	})
	wafInstanceCache.Range(func(key, _ any) bool {
		wafInstanceCache.Delete(key)
		return true
	})
	logger.L.LogInfo("Global WAF and instance caches invalidated")
}

// WAFCacheInvalidator implements domain.WAFCacheInvalidator by clearing the WAF cache.
type WAFCacheInvalidator struct{}

func (WAFCacheInvalidator) Invalidate() {
	InvalidateWAFCache()
}

func wafConfigKey(cfg map[string]string) string {
	keys := slices.Sorted(maps.Keys(cfg))
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cfg[k])
		b.WriteByte(';')
	}
	h := sha256.Sum256([]byte(b.String()))
	return "waf:" + hex.EncodeToString(h[:])
}

// warnUnexecutableDirectives reports SecLang configuration that is no longer
// executed.
//
// The custom_directives field carried operator-written ModSecurity text into
// the Coraza engine. gateon has no SecLang engine now, so the text cannot run.
// Ignoring it silently would leave an operator looking at a populated
// configuration field believing it protects something, which is the same
// failure as a rule that fails to compile and is quietly skipped.
func warnUnexecutableDirectives(directives, routeID string) {
	if strings.TrimSpace(directives) == "" {
		return
	}
	logger.L.LogWarn("custom SecLang directives are configured but no longer executed",
		"route", routeID,
		"detail", "the WAF engine no longer parses SecLang; re-author these as typed rules in the dashboard")
}
