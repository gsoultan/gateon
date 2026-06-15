package middleware

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func (f *Factory) createGraphQLFirewall(cfg map[string]string) (Middleware, error) {
	maxDepth, _ := strconv.Atoi(cfg["max_depth"])
	maxComplexity, _ := strconv.Atoi(cfg["max_complexity"])
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
