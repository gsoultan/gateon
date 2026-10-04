// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
)

func (f *Factory) createAuth(cfg map[string]string) (Middleware, error) {
	authType := cfg["type"]
	baseCfg := f.parseAuthBaseConfig(cfg)

	switch authType {
	case "jwt":
		jwksURL := strings.TrimSpace(cfg["jwks_url"])
		secret := cfg["secret"]
		if secret == "" {
			secret = os.Getenv("GATEON_JWT_SECRET")
		}
		if jwksURL == "" && secret == "" {
			return nil, fmt.Errorf("jwt auth requires jwks_url or secret (or GATEON_JWT_SECRET env)")
		}

		revStore, err := f.revocationStore(cfg)
		if err != nil {
			return nil, err
		}

		jwtCfg := JWTConfig{
			AuthBaseConfig:   baseCfg,
			Issuer:           cfg["issuer"],
			Audience:         cfg["audience"],
			AllowAnyAudience: cfg["allow_any_audience"] == "true",
			JWKSURL:          jwksURL,
			Secret:           []byte(secret),
			RevocationStore:  revStore,
		}
		validator, err := NewJWTValidator(jwtCfg)
		if err != nil {
			return nil, err
		}
		return validator.Handler, nil
	case "paseto":
		secret := cfg["secret"]
		if secret == "" {
			secret = os.Getenv("GATEON_PASETO_SECRET")
		}
		if secret == "" {
			return nil, fmt.Errorf("paseto auth requires config secret or GATEON_PASETO_SECRET env")
		}
		revStore, err := f.revocationStore(cfg)
		if err != nil {
			return nil, err
		}
		verifier, err := NewPasetoVerifier(secret)
		if err != nil {
			return nil, err
		}
		return auth.PasetoAuthWithRevocation(verifier, baseCfg, revStore), nil
	case "apikey":
		hashed := cfg["hashed"] == "true"
		var store APIKeyStore
		if cfg["use_redis"] == "true" && f.redisClient != nil {
			store = NewRedisAPIKeyStore(f.redisClient, cfg["redis_prefix"], hashed)
		} else {
			keys := make(map[string]string)
			for k, v := range cfg {
				if strings.HasPrefix(k, "key_") {
					keys[strings.TrimPrefix(k, "key_")] = v
				}
			}
			if len(keys) == 0 {
				return nil, fmt.Errorf("apikey auth requires at least one key (key_name=value) or use_redis=true")
			}
			store = NewMemoryAPIKeyStore(keys, hashed)
		}

		headerName := cfg["header"]
		if headerName == "" {
			headerName = "X-API-Key"
		}
		queryParam := cfg["query_param"]
		return NewAPIKeyValidator(store, headerName, queryParam, baseCfg).Handler, nil
	case "basic":
		users := cfg["users"]
		if users == "" {
			username := cfg["username"]
			password := cfg["password"]
			if username == "" || password == "" {
				return nil, fmt.Errorf("basic auth requires username and password, or users (user:pass,user2:pass2)")
			}
			return BasicAuthWithConfig(username, password, cfg["realm"], baseCfg), nil
		}
		return BasicAuthUsersWithConfig(users, cfg["realm"], baseCfg)
	case "oidc":
		issuer := strings.TrimSpace(cfg["issuer"])
		if issuer == "" {
			return nil, fmt.Errorf("oidc auth requires issuer URL (e.g. https://auth.example.com)")
		}
		// Before discovery, so a refused config asks the provider nothing.
		revStore, err := f.revocationStore(cfg)
		if err != nil {
			return nil, err
		}
		validator, err := NewOIDCValidator(JWTConfig{
			AuthBaseConfig:   baseCfg,
			Issuer:           issuer,
			Audience:         cfg["audience"],
			AllowAnyAudience: cfg["allow_any_audience"] == "true",
			RevocationStore:  revStore,
		})
		if err != nil {
			return nil, err
		}
		return validator.Handler, nil
	case "oauth2", "oauth2_introspection":
		introURL := strings.TrimSpace(cfg["introspection_url"])
		clientID := strings.TrimSpace(cfg["client_id"])
		clientSecret := cfg["client_secret"]
		if clientSecret == "" {
			clientSecret = os.Getenv("GATEON_OAUTH2_CLIENT_SECRET")
		}
		if introURL == "" || clientID == "" || clientSecret == "" {
			return nil, fmt.Errorf("oauth2 introspection requires introspection_url, client_id, and client_secret (or GATEON_OAUTH2_CLIENT_SECRET env)")
		}
		introCfg := OAuth2IntrospectionConfig{
			AuthBaseConfig:   baseCfg,
			IntrospectionURL: introURL,
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			TokenTypeHint:    strings.TrimSpace(cfg["token_type_hint"]),
			// The management plane's session check, so a session is never
			// posted for introspection (ADR 0051).
			ManagementSessions: f.sessions,
		}
		validator, err := NewOAuth2IntrospectionValidator(introCfg)
		if err != nil {
			return nil, err
		}
		return validator.Handler, nil
	default:
		return nil, fmt.Errorf("unknown auth type: %s (use jwt, paseto, apikey, basic, oidc, or oauth2)", authType)
	}
}

func (f *Factory) parseAuthBaseConfig(cfg map[string]string) AuthBaseConfig {
	base := AuthBaseConfig{
		DryRun:        cfg["dry_run"] == "true",
		ErrorTemplate: cfg["error_template"],
	}

	base.RequiredScopes = parseRequiredScopes(cfg["required_scopes"])
	base.RequiredRoles = kind.ParseListStrict(cfg["required_roles"])

	mappings := make(map[string]string)
	for k, v := range cfg {
		if strings.HasPrefix(k, "map_claim_") {
			claim := strings.TrimPrefix(k, "map_claim_")
			mappings[claim] = v
		}
	}
	base.ClaimMappings = mappings

	return base
}

// parseRequiredScopes reads required_scopes as the dashboard documents it:
// separated by commas, spaces or both ("read, write", "read write"). It split
// on "," alone and kept the space, so " write" matched no token's scope and
// every valid token was refused (ADR 0046). A scope never contains a space
// (RFC 6749 section 3.3), which is what makes a space a separator here.
func parseRequiredScopes(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// revocationStore is the revocation list an auth middleware with "Enable
// Revocation" on checks: the Redis keys "<revocation_prefix><jti>". With the
// switch on and no Redis it refuses the build -- there is nowhere a revoked
// token could be recorded -- rather than build a check that reads nothing
// (ADR 0046). The router serves a security middleware that cannot be built as
// a refusal, so a route that relied on revocation is not opened by it.
func (f *Factory) revocationStore(cfg map[string]string) (RevocationStore, error) {
	on, err := kind.ParseBoolStrict(cfg["enable_revocation"], false)
	if err != nil {
		return nil, kind.CfgError("enable_revocation", cfg["enable_revocation"], err)
	}
	if !on {
		return nil, nil
	}
	if f.redisClient == nil {
		return nil, kind.CfgError("enable_revocation", cfg["enable_revocation"], auth.ErrRevocationNeedsRedis)
	}
	return NewRedisRevocationStore(f.redisClient, cfg["revocation_prefix"]), nil
}
