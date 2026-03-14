package middleware

import (
	"fmt"
	"regexp"
	"strings"
)

func (f *Factory) createRewrite(cfg map[string]string) (Middleware, error) {
	rewriteCfg := RewriteConfig{
		Path:     cfg["path"],
		AddQuery: make(map[string]string),
	}

	if pattern := cfg["pattern"]; pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrite pattern: %w", err)
		}
		rewriteCfg.Regexp = re
		rewriteCfg.Replacement = cfg["replacement"]
	}

	for k, v := range cfg {
		if strings.HasPrefix(k, "query_") {
			rewriteCfg.AddQuery[strings.TrimPrefix(k, "query_")] = v
		}
	}

	return Rewrite(rewriteCfg), nil
}
