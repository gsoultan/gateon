package middleware

import (
	"fmt"
	"os"
	"strings"
)

func (f *Factory) createAuth(cfg map[string]string) (Middleware, error) {
	authType := cfg["type"]
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
		jwtCfg := JWTConfig{
			Issuer:   cfg["issuer"],
			Audience: cfg["audience"],
			JWKSURL:  jwksURL,
			Secret:   []byte(secret),
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
		return PasetoAuth(verifier), nil
	case "apikey":
		keys := make(map[string]string)
		for k, v := range cfg {
			if strings.HasPrefix(k, "key_") {
				keys[strings.TrimPrefix(k, "key_")] = v
			}
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("apikey auth requires at least one key (key_name=value)")
		}
		headerName := cfg["header"]
		if headerName == "" {
			headerName = "X-API-Key"
		}
		queryParam := cfg["query_param"]
		return NewAPIKeyValidator(keys, headerName, queryParam).Handler, nil
	case "basic":
		users := cfg["users"]
		if users == "" {
			username := cfg["username"]
			password := cfg["password"]
			if username == "" || password == "" {
				return nil, fmt.Errorf("basic auth requires username and password, or users (user:pass,user2:pass2)")
			}
			return BasicAuthWithRealm(username, password, cfg["realm"]), nil
		}
		return BasicAuthUsers(users, cfg["realm"])
	case "oidc":
		issuer := strings.TrimSpace(cfg["issuer"])
		if issuer == "" {
			return nil, fmt.Errorf("oidc auth requires issuer URL (e.g. https://auth.example.com)")
		}
		audience := strings.TrimSpace(cfg["audience"])
		validator, err := NewOIDCValidator(issuer, audience)
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
