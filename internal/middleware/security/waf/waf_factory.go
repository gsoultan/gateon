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
// value goes through here rather than through assignment. An empty value is
// missing: the parser reads it as the default, so treating it as a choice
// would hand the route the route default instead of the global value.
func setIfMissing(cfg map[string]string, key, val string) {
	if cur, ok := cfg[key]; !ok || strings.TrimSpace(cur) == "" {
		cfg[key] = val
	}
}

// Effective is what a WAF runs, as the dashboard shows it: read from the
// config the engine is built from, after the tier baseline, the global WAF's
// fixed choices and a route's inheritance are applied -- never from the raw
// switches, which is how the global card came to show categories OFF while
// they were enforced (truth T8) and an audit-only WAF as protecting (T12).
type Effective struct {
	// Mode is "enforcing", "audit_only", or "off" when there is no WAF.
	Mode          string `json:"mode"`
	ParanoiaLevel int    `json:"paranoiaLevel"`
	// Categories maps each switch key (sqli, xss, ..., malware_detection) to
	// whether its rules run.
	Categories map[string]bool `json:"categories"`
}

// Mode values for Effective.
const (
	ModeEnforcing = "enforcing"
	ModeAuditOnly = "audit_only"
	ModeOff       = "off"
)

// effectiveCategoryKeys are the switches Effective reports, in the order the
// dashboard lists them. dos_protection is not among them: no rule reads it.
var effectiveCategoryKeys = []string{
	keySQLi, keyXSS, keyLFI, keyRCE, keyPHP, keyJava, keyNodeJS, keyScanner, keyProtocol,
	keyWordPress, keyMalware, keyRansomware, keyDLP, keyIPReputation,
}

// The route config keys of the WAF's switches, as parseWAFConfig reads them.
const (
	keySQLi         = "sqli"
	keyXSS          = "xss"
	keyLFI          = "lfi"
	keyRCE          = "rce"
	keyPHP          = "php"
	keyJava         = "java"
	keyNodeJS       = "nodejs"
	keyScanner      = "scanner"
	keyProtocol     = "protocol"
	keyWordPress    = "wordpress"
	keyMalware      = "malware_detection"
	keyRansomware   = "ransomware_detection"
	keyDLP          = "dlp"
	keyIPReputation = "ip_reputation"
)

// EffectiveGlobal reports what the gateway-wide WAF runs on a route with no
// WAF of its own.
func EffectiveGlobal(ctx context.Context, store config.GlobalConfigStore) Effective {
	w := enabledWAF(storedGlobal(ctx, store))
	if w == nil {
		return Effective{Mode: ModeOff, Categories: map[string]bool{}}
	}
	return summarize(globalWAFConfig(w, resolveWAFTier(w), security.Deps{GlobalStore: store}))
}

// EffectiveRoute reports what a route WAF with config cfg runs: cfg merged
// over the global WAF exactly as NewWAF merges it. cfg is not modified.
func EffectiveRoute(ctx context.Context, cfg map[string]string, store config.GlobalConfigStore) Effective {
	merged := maps.Clone(cfg)
	if merged == nil {
		merged = map[string]string{}
	}
	mergeGlobalWAF(merged, enabledWAF(storedGlobal(ctx, store)), security.Deps{GlobalStore: store})
	return summarize(parseWAFConfig(merged))
}

func storedGlobal(ctx context.Context, store config.GlobalConfigStore) *gateonv1.GlobalConfig {
	if store == nil {
		return nil
	}
	return store.Get(ctx)
}

func summarize(c WAFConfig) Effective {
	settings := inheritedSettings(c)
	out := Effective{Mode: ModeEnforcing, ParanoiaLevel: c.ParanoiaLevel, Categories: make(map[string]bool, len(effectiveCategoryKeys))}
	if c.AuditOnly {
		out.Mode = ModeAuditOnly
	}
	for _, k := range effectiveCategoryKeys {
		out.Categories[k] = settings[k] == "true"
	}
	return out
}

// enabledGlobalWAF is the gateway-wide WAF config when the global WAF is on,
// and nil when it is absent or off.
func enabledGlobalWAF(d security.Deps) *gateonv1.WafConfig {
	return enabledWAF(storedGlobal(context.TODO(), d.GlobalStore))
}

// enabledWAF is g's WAF config when it is switched on, and nil otherwise.
func enabledWAF(g *gateonv1.GlobalConfig) *gateonv1.WafConfig {
	if g == nil || g.Waf == nil || !g.Waf.Enabled {
		return nil
	}
	return g.Waf
}

// mergeGlobalWAFDefaults fills unset per-route settings from the gateway-wide
// WAF and returns its custom directives. Nothing happens unless the global WAF
// is both present and enabled.
//
// A route with its own WAF skips the global one (router.go), so what the route
// does not say it inherits -- and it inherits what the global WAF actually
// runs, not the raw proto booleans. The two differ: NewGlobalWAF turns malware
// and ransomware detection on whatever malware_detection says, applies the
// tier's baseline, and ignores the category booleans, whose zero value is
// "unset" (ADR 0044). Copying the booleans meant attaching a default WAF to a
// route switched those rules off there: /c99.php went from 403 to 200 (truth
// T7). A route adds to or narrows the global policy only by saying so: a key
// it sets wins, a key it leaves out is the global WAF's.
func mergeGlobalWAFDefaults(cfg map[string]string, d security.Deps) string {
	return mergeGlobalWAF(cfg, enabledGlobalWAF(d), d)
}

// mergeGlobalWAF is mergeGlobalWAFDefaults for an already-read global WAF
// config w, nil when the global WAF is off.
func mergeGlobalWAF(cfg map[string]string, w *gateonv1.WafConfig, d security.Deps) string {
	if w == nil {
		return ""
	}
	effective := globalWAFConfig(w, resolveWAFTier(w), d)
	for key, val := range inheritedSettings(effective) {
		setIfMissing(cfg, key, val)
	}
	applyGlobalCRSTunables(cfg, w, d.DataDir)
	return w.CustomDirectives
}

// inheritedSettings renders a WAF config as the route config keys parseWAFConfig
// reads, so that a route parsing them gets the same engine settings. Lists are
// included only when non-empty, since an empty one and an unset one read the
// same.
func inheritedSettings(c WAFConfig) map[string]string {
	b := strconv.FormatBool
	out := map[string]string{
		keySQLi: b(!c.DisableSQLI), keyXSS: b(!c.DisableXSS), keyLFI: b(!c.DisableLFI),
		keyRCE: b(!c.DisableRCE), keyPHP: b(!c.DisablePHP), keyScanner: b(!c.DisableScanner),
		keyProtocol: b(!c.DisableProtocol), keyJava: b(!c.DisableJava), keyNodeJS: b(!c.DisableNodeJS),
		keyWordPress:      b(!c.DisableWordPress),
		keyIPReputation:   b(c.EnableIPReputation),
		keyMalware:        b(c.EnableMalwareDetection),
		keyRansomware:     b(c.EnableRansomwareDetection),
		keyDLP:            b(c.EnableDLP),
		"audit_only":      b(c.AuditOnly),
		"paranoia_level":  strconv.Itoa(c.ParanoiaLevel),
		"ssrf_protection": b(c.EnableSSRFProtection),
		// Cloudflare trust is a fact about where the gateway sits.
		"trust_cloudflare_headers":      b(c.TrustCloudflare),
		"audit_log_relevant_only":       b(c.AuditLogRelevantOnly),
		"disable_entropy":               b(c.DisableEntropy),
		"enable_body_entropy":           b(c.EnableBodyEntropy),
		"enable_fingerprint_validation": b(c.EnableFingerprintValidation),
		"enable_confidence_scoring":     b(c.EnableConfidenceScoring),
	}
	if len(c.AppProfiles) > 0 {
		out["app_profiles"] = strings.Join(c.AppProfiles, ",")
	}
	if len(c.Origins) > 0 {
		out["origins"] = strings.Join(c.Origins, ",")
	}
	return out
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
