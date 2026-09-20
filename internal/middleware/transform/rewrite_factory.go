// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewRewrite(cfg map[string]string) (kind.Middleware, error) {
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
