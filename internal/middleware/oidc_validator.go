package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// oidcDiscoveryResponse represents the OpenID Connect Discovery document.
type oidcDiscoveryResponse struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

const oidcDiscoveryTimeout = 15 * time.Second

// NewOIDCValidator creates a JWT validator by fetching OIDC discovery from the issuer.
// Config: issuer (required), audience (optional), baseCfg.
func NewOIDCValidator(issuer, audience string, baseCfg AuthBaseConfig) (*JWTValidator, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("oidc auth requires issuer URL")
	}
	issuer = strings.TrimSuffix(issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: oidcDiscoveryTimeout}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery returned %d", resp.StatusCode)
	}

	var disc oidcDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("oidc discovery invalid JSON: %w", err)
	}
	if disc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery missing jwks_uri")
	}

	// Use issuer from discovery if config issuer was a base URL
	effectiveIssuer := disc.Issuer
	if effectiveIssuer == "" {
		effectiveIssuer = issuer
	}

	jwtCfg := JWTConfig{
		AuthBaseConfig: baseCfg,
		Issuer:         strings.TrimSuffix(effectiveIssuer, "/"),
		Audience:       strings.TrimSpace(audience),
		JWKSURL:        disc.JWKSURI,
	}
	return NewJWTValidator(jwtCfg)
}
