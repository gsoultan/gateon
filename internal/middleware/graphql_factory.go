package middleware

import (
	"encoding/json"
	"strconv"
)

func (f *Factory) createGraphQLFirewall(cfg map[string]string) (Middleware, error) {
	maxDepth, _ := strconv.Atoi(cfg["max_depth"])
	maxComplexity, _ := strconv.Atoi(cfg["max_complexity"])
	introspection := cfg["introspection"] == "true"

	fieldCosts := make(map[string]int)
	if costsJson, ok := cfg["field_costs"]; ok {
		_ = json.Unmarshal([]byte(costsJson), &fieldCosts)
	}

	fieldClaims := make(map[string]string)
	if claimsJson, ok := cfg["field_claims"]; ok {
		_ = json.Unmarshal([]byte(claimsJson), &fieldClaims)
	}

	return GraphQLFirewall(GraphQLFirewallConfig{
		MaxDepth:      maxDepth,
		MaxComplexity: maxComplexity,
		Introspection: introspection,
		FieldCosts:    fieldCosts,
		FieldClaims:   fieldClaims,
	}), nil
}
