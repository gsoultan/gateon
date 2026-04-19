package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/httputil"
)

// AuthBaseConfig contains common authentication configuration fields.
type AuthBaseConfig struct {
	DryRun         bool              `json:"dry_run,omitzero"`
	RequiredScopes []string          `json:"required_scopes,omitzero"`
	RequiredRoles  []string          `json:"required_roles,omitzero"`
	ClaimMappings  map[string]string `json:"claim_mappings,omitzero"`
	ErrorTemplate  string            `json:"error_template,omitzero"` // Optional custom error message
}

// ValidateClaims checks if the given claims satisfy the required scopes and roles.
func (c AuthBaseConfig) ValidateClaims(claims any) error {
	m := ToMap(claims)
	if err := c.validateScopes(m); err != nil {
		return err
	}
	return c.validateRoles(m)
}

func (c AuthBaseConfig) validateScopes(claims map[string]any) error {
	if len(c.RequiredScopes) == 0 {
		return nil
	}

	rawScopes, ok := claims["scope"]
	if !ok {
		rawScopes, ok = claims["scp"]
	}

	var scopes []string
	if ok {
		switch s := rawScopes.(type) {
		case string:
			scopes = strings.Fields(s)
		case []any:
			for _, v := range s {
				if str, ok := v.(string); ok {
					scopes = append(scopes, str)
				}
			}
		case []string:
			scopes = s
		}
	}

	for _, req := range c.RequiredScopes {
		found := false
		for _, s := range scopes {
			if s == req {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required scope: %s", req)
		}
	}
	return nil
}

func (c AuthBaseConfig) validateRoles(claims map[string]any) error {
	if len(c.RequiredRoles) == 0 {
		return nil
	}

	rawRoles, ok := claims["roles"]
	if !ok {
		rawRoles, ok = claims["groups"]
	}

	var roles []string
	if ok {
		switch r := rawRoles.(type) {
		case []any:
			for _, v := range r {
				if str, ok := v.(string); ok {
					roles = append(roles, str)
				}
			}
		case []string:
			roles = r
		case string:
			roles = strings.Split(r, ",")
		}
	}

	for _, req := range c.RequiredRoles {
		found := false
		for _, r := range roles {
			if strings.TrimSpace(r) == req {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required role: %s", req)
		}
	}
	return nil
}

// MapClaimsToHeaders injects mapped claims into the request headers.
func (c AuthBaseConfig) MapClaimsToHeaders(r *http.Request, claims any) {
	m := ToMap(claims)
	for claim, header := range c.ClaimMappings {
		if val, ok := m[claim]; ok {
			r.Header.Set(header, fmt.Sprintf("%v", val))
		}
	}
}

// HandleFailure handles an authentication failure based on DryRun and ErrorTemplate.
func (c AuthBaseConfig) HandleFailure(w http.ResponseWriter, r *http.Request, next http.Handler, err error) {
	if c.DryRun {
		// Log error but continue
		next.ServeHTTP(w, r)
		return
	}

	msg := err.Error()
	if c.ErrorTemplate != "" {
		msg = c.ErrorTemplate
	}

	httputil.WriteJSONError(w, http.StatusUnauthorized, msg, "")
}

// InjectContext injects auth metadata into context.
func InjectContext(ctx context.Context, claims any) context.Context {
	ctx = context.WithValue(ctx, UserContextKey, claims)

	// Attempt to extract tenant_id/sub for standard context keys
	m := ToMap(claims)
	var tenantID string
	if tid, ok := m["tenant_id"].(string); ok {
		tenantID = tid
	} else if sub, ok := m["sub"].(string); ok {
		tenantID = sub
	}

	if tenantID != "" {
		ctx = context.WithValue(ctx, TenantIDContextKey, tenantID)
	}

	return ctx
}

// ToMap converts various map types to map[string]any.
func ToMap(claims any) map[string]any {
	if m, ok := claims.(map[string]any); ok {
		return m
	}
	if m, ok := claims.(map[string]interface{}); ok {
		return m
	}
	if m, ok := claims.(interface{ ToMap() map[string]any }); ok {
		return m.ToMap()
	}
	return make(map[string]any)
}
