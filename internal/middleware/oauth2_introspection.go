package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth2IntrospectionConfig configures OAuth 2.0 token introspection (RFC 7662).
type OAuth2IntrospectionConfig struct {
	AuthBaseConfig
	IntrospectionURL string // Required
	ClientID         string // Required
	ClientSecret     string // Required
	TokenTypeHint    string // Optional: "access_token" or "refresh_token"
}

// oauth2IntrospectionResponse is the RFC 7662 introspection response.
type oauth2IntrospectionResponse struct {
	Active bool                   `json:"active"`
	Sub    string                 `json:"sub,omitempty"`
	Scope  string                 `json:"scope,omitempty"`
	Extras map[string]interface{} `json:"-"`
}

// UnmarshalJSON allows capturing extra claims.
func (r *oauth2IntrospectionResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["active"].(bool); ok {
		r.Active = v
	}
	if v, ok := raw["sub"].(string); ok {
		r.Sub = v
	}
	if v, ok := raw["scope"].(string); ok {
		r.Scope = v
	}
	r.Extras = raw
	return nil
}

const oauth2IntrospectionTimeout = 10 * time.Second

// OAuth2IntrospectionValidator validates opaque access tokens via RFC 7662 introspection.
type OAuth2IntrospectionValidator struct {
	config OAuth2IntrospectionConfig
	client *http.Client
}

// NewOAuth2IntrospectionValidator creates an OAuth 2.0 introspection validator.
func NewOAuth2IntrospectionValidator(cfg OAuth2IntrospectionConfig) (*OAuth2IntrospectionValidator, error) {
	cfg.IntrospectionURL = strings.TrimSpace(cfg.IntrospectionURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	if cfg.IntrospectionURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("oauth2 introspection requires introspection_url, client_id, and client_secret")
	}
	client := &http.Client{Timeout: oauth2IntrospectionTimeout}
	return &OAuth2IntrospectionValidator{config: cfg, client: client}, nil
}

// Handler returns a middleware that validates tokens via OAuth 2.0 introspection.
func (v *OAuth2IntrospectionValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ExtractToken(r)
		if token == "" {
			v.config.HandleFailure(w, r, next, fmt.Errorf("authorization header or token query required"))
			return
		}

		resp, err := v.introspect(r.Context(), token)
		if err != nil {
			v.config.HandleFailure(w, r, next, fmt.Errorf("token introspection failed: %v", err))
			return
		}
		if !resp.Active {
			v.config.HandleFailure(w, r, next, fmt.Errorf("token inactive or invalid"))
			return
		}

		claims := make(map[string]any)
		claims["sub"] = resp.Sub
		claims["scope"] = resp.Scope
		for k, val := range resp.Extras {
			claims[k] = val
		}

		if err := v.config.ValidateClaims(claims); err != nil {
			v.config.HandleFailure(w, r, next, err)
			return
		}

		ctx := InjectContext(r.Context(), claims)
		v.config.MapClaimsToHeaders(r, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (v *OAuth2IntrospectionValidator) introspect(ctx context.Context, token string) (*oauth2IntrospectionResponse, error) {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", v.config.ClientID)
	form.Set("client_secret", v.config.ClientSecret)
	if v.config.TokenTypeHint != "" {
		form.Set("token_type_hint", v.config.TokenTypeHint)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.config.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned %d: %s", resp.StatusCode, string(body))
	}

	var result oauth2IntrospectionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid introspection response: %w", err)
	}
	return &result, nil
}
