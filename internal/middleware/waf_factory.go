package middleware

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
func (f *Factory) CreateGlobalWAF() (Middleware, error) {
	if f.globalStore == nil {
		return nil, nil
	}
	g := f.globalStore.Get(context.TODO())
	if g == nil || g.Waf == nil || !g.Waf.GetEnabled() {
		return nil, nil
	}
	w := g.Waf

	// gRPC relaxations are keyed on the trusted route type, so the gateway-wide
	// WAF is memoized as two distinct variants (strict vs gRPC-relaxed). An HTTP
	// route never receives the gRPC-relaxed instance, so a spoofed Content-Type
	// cannot disable its body inspection.
	grpcMode := f.isGRPCRoute()
	// The resolved tier may come from the global profile (env/config), which is
	// not part of the WAF proto, so it must be in the cache key alongside the
	// proto hash and the gRPC variant.
	tier := resolveWAFTier(w)
	key := "global-waf:" + string(tier) + ":" + strconv.FormatBool(grpcMode) + ":" + hashWAFProto(w)
	if cached, ok := globalWAFCache.Load(key); ok {
		return cached.(Middleware), nil
	}

	pl := int(w.GetParanoiaLevel())
	if pl < 1 {
		pl = 1
	}
	cfg := WAFConfig{
		UseCRS:        w.GetUseCrs(),
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
		AnomalyThreshold:          int(w.GetAnomalyThreshold()),
		RequestBodyLimit:          int(w.GetRequestBodyLimit()),
		ResponseBodyLimit:         int(w.GetResponseBodyLimit()),
		AuditLogPath:              w.GetAuditLogPath(),
		AuditLogRelevantOnly:      w.GetAuditLogRelevantOnly(),
		AllowedAdminIps:           w.GetAllowedAdminIps(),
		EntropyThreshold:          w.GetEntropyThreshold(),
		DisableEntropy:            w.GetDisableEntropy(),
		TrustCloudflare:           w.GetTrustCloudflareHeaders(),
		GlobalDirectives:          w.GetCustomDirectives(),
		RouteID:                   "gateon-global-waf",
		EbpfManager:               f.ebpfManager,
		Reputation:                f.reputation,
		GRPCMode:                  grpcMode,
	}
	// Apply the resolved tier baseline, then honour an explicit DLP opt-in as an
	// upgrade: a user who deliberately enabled DLP gets response inspection even
	// at the standard tier, while DLP stays off by default below enterprise.
	applyWAFTier(&cfg, tier)
	if w.GetDlp() {
		cfg.EnableDLP = true
		cfg.EnableResponseInspection = true
	}

	// When auto-update has fetched fresh rules to disk, prefer them.
	if w.GetAutoUpdateRules() {
		rulesPath := filepath.Join(f.dataDir, "waf", "rules")
		if _, err := os.Stat(rulesPath); err == nil {
			cfg.RulesPath = rulesPath
		}
	}

	mw, err := WAF(cfg)
	if err != nil {
		return nil, err
	}
	globalWAFCache.Store(key, mw)
	return mw, nil
}

func hashWAFProto(w *gateonv1.WafConfig) string {
	b, err := proto.Marshal(w)
	if err != nil {
		return "nohash"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (f *Factory) createWAF(cfg map[string]string) (Middleware, error) {
	globalDirectives := ""
	if f.globalStore != nil {
		global := f.globalStore.Get(context.TODO())
		if global != nil && global.Waf != nil && global.Waf.Enabled {
			globalDirectives = global.Waf.CustomDirectives

			// Merge global settings into cfg as defaults if not explicitly set
			setIfMissing := func(key string, val bool) {
				if _, ok := cfg[key]; !ok {
					cfg[key] = strconv.FormatBool(val)
				}
			}
			if global.Waf.UseCrs {
				setIfMissing("sqli", global.Waf.Sqli)
				setIfMissing("xss", global.Waf.Xss)
				setIfMissing("lfi", global.Waf.Lfi)
				setIfMissing("rce", global.Waf.Rce)
				setIfMissing("php", global.Waf.Php)
				setIfMissing("scanner", global.Waf.Scanner)
				setIfMissing("protocol", global.Waf.Protocol)
				setIfMissing("java", global.Waf.Java)
				setIfMissing("nodejs", global.Waf.Nodejs)
				setIfMissing("wordpress", global.Waf.Wordpress)
				setIfMissing("ip_reputation", global.Waf.IpReputation)
				setIfMissing("dos_protection", global.Waf.DosProtection)
				setIfMissing("malware_detection", global.Waf.MalwareDetection)
				setIfMissing("ransomware_detection", global.Waf.RansomwareDetection)
				setIfMissing("dlp", global.Waf.Dlp)
				if _, ok := cfg["anomaly_threshold"]; !ok && global.Waf.AnomalyThreshold > 0 {
					cfg["anomaly_threshold"] = strconv.Itoa(int(global.Waf.AnomalyThreshold))
				}
				if _, ok := cfg["request_body_limit"]; !ok && global.Waf.RequestBodyLimit > 0 {
					cfg["request_body_limit"] = strconv.Itoa(int(global.Waf.RequestBodyLimit))
				}
				if _, ok := cfg["response_body_limit"]; !ok && global.Waf.ResponseBodyLimit > 0 {
					cfg["response_body_limit"] = strconv.Itoa(int(global.Waf.ResponseBodyLimit))
				}
				if _, ok := cfg["audit_log_path"]; !ok && global.Waf.AuditLogPath != "" {
					cfg["audit_log_path"] = global.Waf.AuditLogPath
				}
				if _, ok := cfg["audit_log_relevant_only"]; !ok {
					cfg["audit_log_relevant_only"] = strconv.FormatBool(global.Waf.AuditLogRelevantOnly)
				}
				if _, ok := cfg["allowed_admin_ips"]; !ok && len(global.Waf.AllowedAdminIps) > 0 {
					cfg["allowed_admin_ips"] = strings.Join(global.Waf.AllowedAdminIps, ",")
				}
				if _, ok := cfg["entropy_threshold"]; !ok && global.Waf.EntropyThreshold > 0 {
					cfg["entropy_threshold"] = strconv.FormatFloat(global.Waf.EntropyThreshold, 'f', -1, 64)
				}
				if _, ok := cfg["disable_entropy"]; !ok {
					cfg["disable_entropy"] = strconv.FormatBool(global.Waf.DisableEntropy)
				}
				if _, ok := cfg["trust_cloudflare_headers"]; !ok {
					cfg["trust_cloudflare_headers"] = strconv.FormatBool(global.Waf.TrustCloudflareHeaders)
				}

				if global.Waf.AutoUpdateRules {
					rulesPath := filepath.Join(f.dataDir, "waf", "rules")
					if _, err := os.Stat(rulesPath); err == nil {
						cfg["rules_path"] = rulesPath
					}
				}
			}
		}
	}

	grpcMode := f.isGRPCRoute()
	key := wafConfigKey(cfg) + ":" + globalDirectives + ":grpc=" + strconv.FormatBool(grpcMode)
	if cached, ok := wafCache.Load(key); ok {
		return cached.(Middleware), nil
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.GlobalDirectives = globalDirectives
	wafCfg.EbpfManager = f.ebpfManager
	wafCfg.Reputation = f.reputation
	wafCfg.GRPCMode = grpcMode

	mw, err := WAF(wafCfg)
	if err != nil {
		return nil, err
	}
	wafCache.Store(key, mw)
	return mw, nil
}

// InvalidateWAFCache clears all cached WAF instances. Call when a WAF middleware is saved or deleted.
func InvalidateWAFCache() {
	wafCache.Range(func(key, _ any) bool {
		wafCache.Delete(key)
		return true
	})
	globalWAFCache.Range(func(key, _ any) bool {
		globalWAFCache.Delete(key)
		return true
	})
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
