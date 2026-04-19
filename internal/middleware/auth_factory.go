package middleware

import (
	"fmt"
	"os"
	"strings"
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

		var revStore RevocationStore
		if cfg["enable_revocation"] == "true" && f.redisClient != nil {
			revStore = NewRedisRevocationStore(f.redisClient, cfg["revocation_prefix"])
		}

		jwtCfg := JWTConfig{
			AuthBaseConfig:  baseCfg,
			Issuer:          cfg["issuer"],
			Audience:        cfg["audience"],
			JWKSURL:         jwksURL,
			Secret:          []byte(secret),
			RevocationStore: revStore,
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
		verifier, err := NewPasetoVerifier(secret)
		if err != nil {
			return nil, err
		}
		return PasetoAuth(verifier, baseCfg), nil
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
		audience := strings.TrimSpace(cfg["audience"])
		validator, err := NewOIDCValidator(issuer, audience, baseCfg)
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

	if scopes := cfg["required_scopes"]; scopes != "" {
		base.RequiredScopes = strings.Split(scopes, ",")
	}
	if roles := cfg["required_roles"]; roles != "" {
		base.RequiredRoles = strings.Split(roles, ",")
	}

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
