// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"encoding/json"
	"fmt"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func NewGraphQLFirewall(cfg map[string]string) (kind.Middleware, error) {
	// Honoured rather than discarded: both limits treat 0 as "no limit"
	// (see serveGraphQLFirewall), so a typo here is the protection switched
	// off while the dashboard still shows what the operator typed.
	maxDepth, err := kind.ParseIntStrict(cfg["max_depth"], 0)
	if err != nil {
		return nil, kind.CfgError("max_depth", cfg["max_depth"], err)
	}
	maxComplexity, err := kind.ParseIntStrict(cfg["max_complexity"], 0)
	if err != nil {
		return nil, kind.CfgError("max_complexity", cfg["max_complexity"], err)
	}
	introspection := cfg["introspection"] == "true"

	fieldCosts := make(map[string]int)
	if costsJson, ok := cfg["field_costs"]; ok {
		if err := json.Unmarshal([]byte(costsJson), &fieldCosts); err != nil {
			return nil, fmt.Errorf("graphql firewall: invalid field_costs JSON: %w", err)
		}
	}

	fieldClaims := make(map[string]string)
	if claimsJson, ok := cfg["field_claims"]; ok {
		if err := json.Unmarshal([]byte(claimsJson), &fieldClaims); err != nil {
			return nil, fmt.Errorf("graphql firewall: invalid field_claims JSON: %w", err)
		}
	}

	return GraphQLFirewall(GraphQLFirewallConfig{
		MaxDepth:      maxDepth,
		MaxComplexity: maxComplexity,
		Introspection: introspection,
		FieldCosts:    fieldCosts,
		FieldClaims:   fieldClaims,
	}), nil
}
