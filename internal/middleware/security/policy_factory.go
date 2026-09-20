// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewPolicy(cfg map[string]string) (kind.Middleware, error) {
	var rules []PolicyRule
	for k, v := range cfg {
		if strings.HasPrefix(k, "rule_") {
			name := strings.TrimPrefix(k, "rule_")
			msgKey := "message_" + name
			rules = append(rules, PolicyRule{
				Expression: v,
				Message:    cfg[msgKey],
			})
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("policy middleware requires at least one rule (rule_name=expression)")
	}

	return Policy(PolicyConfig{Rules: rules})
}
