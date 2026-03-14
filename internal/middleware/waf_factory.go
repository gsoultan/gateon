package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

var wafCache sync.Map

func (f *Factory) createWAF(cfg map[string]string) (Middleware, error) {
	key := wafConfigKey(cfg)
	if cached, ok := wafCache.Load(key); ok {
		return cached.(Middleware), nil
	}
	mw, err := WAF(parseWAFConfig(cfg))
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
