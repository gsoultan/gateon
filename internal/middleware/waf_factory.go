package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var wafCache sync.Map

func (f *Factory) createWAF(cfg map[string]string) (Middleware, error) {
	globalDirectives := ""
	if f.globalStore != nil {
		global := f.globalStore.Get(nil)
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

				if global.Waf.AutoUpdateRules {
					rulesPath := filepath.Join(f.dataDir, "waf", "rules")
					if _, err := os.Stat(rulesPath); err == nil {
						cfg["rules_path"] = rulesPath
					}
				}
			}
		}
	}

	key := wafConfigKey(cfg) + ":" + globalDirectives
	if cached, ok := wafCache.Load(key); ok {
		return cached.(Middleware), nil
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.GlobalDirectives = globalDirectives
	wafCfg.EbpfManager = f.ebpfManager

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
