package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
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
			}
		}
	}

	key := wafConfigKey(cfg) + ":" + globalDirectives
	if cached, ok := wafCache.Load(key); ok {
		return cached.(Middleware), nil
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.GlobalDirectives = globalDirectives

	mw, err := WAF(wafCfg)
	if err != nil {
		return nil, err
	}
	wafCache.Store(key, mw)
	return mw, nil
}

// InvalidateWAFCache clears all cached WAF instances. Call when a WAF middleware is saved or deleted.
func InvalidateWAFCache() {
	wafCache.Range(func(key, _ interface{}) bool {
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
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
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
