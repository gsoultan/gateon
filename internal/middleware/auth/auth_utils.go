// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/request"
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
//
// A mapped header is one the backend has been told to read as the verified
// token's value, so a claim absent from the token must remove the header
// rather than leave the client's own copy in place.
func (c AuthBaseConfig) MapClaimsToHeaders(r *http.Request, claims any) {
	m := ToMap(claims)
	for claim, header := range c.ClaimMappings {
		if val, ok := m[claim]; ok {
			r.Header.Set(header, fmt.Sprintf("%v", val))
		} else {
			r.Header.Del(header)
		}
	}
}

// usesClaims reports whether anything in this configuration reads a claim, so a
// credential type that has to assemble its claims can skip that when nothing
// will look at them.
func (c AuthBaseConfig) usesClaims() bool {
	return len(c.RequiredScopes) > 0 || len(c.RequiredRoles) > 0 || len(c.ClaimMappings) > 0
}

// authorizeCredential holds a credential that is not a token -- an API key's
// tenant, a basic-auth login's username -- to the checks a verified token goes
// through: required scopes and roles against the claims it can offer, then the
// claim-to-header mapping. Neither kind carries a role or a scope, so a route
// that requires one refuses them, just as it refuses a token without the role.
func (c AuthBaseConfig) authorizeCredential(r *http.Request, claims map[string]any) error {
	if err := c.ValidateClaims(claims); err != nil {
		return err
	}
	c.MapClaimsToHeaders(r, claims)
	return nil
}

// stripMappedHeaders removes the client's copies of every mapped claim header.
// A request let past authentication without a credential -- a CORS preflight,
// which a browser sends without one -- must not carry them to the backend
// either: a mapped header is only ever the gateway's to set.
func (c AuthBaseConfig) stripMappedHeaders(r *http.Request) {
	for _, header := range c.ClaimMappings {
		r.Header.Del(header)
	}
}

// HandleFailure handles an authentication failure based on DryRun and ErrorTemplate.
func (c AuthBaseConfig) HandleFailure(w http.ResponseWriter, r *http.Request, next http.Handler, err error) {
	if c.DryRun {
		// Continue, but without the client's copies of the mapped identity
		// headers: only a verified token may set those, and there is none.
		c.MapClaimsToHeaders(r, nil)
		next.ServeHTTP(w, r)
		return
	}

	// Authentication refused it: of the refusals the gateway writes before a
	// request reaches its service, the kind brute-force detection counts
	// (request.RefusalAuthentication, ADR 0059). A token refusal is marked as
	// one first (refuseToken) and keeps that mark.
	if rs := request.GetRequestState(r); rs != nil && rs.Refused == request.RefusalNone {
		rs.Refused = request.RefusalAuthentication
	}

	msg := err.Error()
	if c.ErrorTemplate != "" {
		msg = c.ErrorTemplate
	}

	httputil.WriteJSONError(w, http.StatusUnauthorized, msg, "")
}

// refuseToken is HandleFailure for a request refused because the token it
// presented failed the gateway's own verification: invalid, expired, revoked,
// unverifiable or short of the route's scopes and roles. It marks the request
// so (request.RefusalToken): a client re-presenting a token it was issued --
// a GraphQL or Connect poller whose session expired, the dashboard's own tab
// among them -- is not guessing a password, and the brute-force detectors
// used to shun it as if it were (ADR 0031).
//
// Called only after a token was found and checked; a request that presented
// none is refused by HandleFailure and stays a possible attempt. In dry run
// nothing is refused, so nothing is marked.
func (c AuthBaseConfig) refuseToken(w http.ResponseWriter, r *http.Request, next http.Handler, err error) {
	if !c.DryRun {
		request.MarkRefused(r, request.RefusalToken)
	}
	c.HandleFailure(w, r, next, err)
}

// authNotRequiredKey carries the management base handler's decision that a
// request needs no credential. An unexported struct type, so no string key
// from anywhere else can forge it.
type authNotRequiredKey struct{}

// WithAuthNotRequired records on ctx that the management base handler decided
// this request needs no credential: authentication is off for the deployment,
// or the path must work before there is a session (setup, sign-in, the second
// factor, health). Only that handler calls it.
func WithAuthNotRequired(ctx context.Context) context.Context {
	return context.WithValue(ctx, authNotRequiredKey{}, true)
}

// AuthNotRequired reports whether ctx carries that decision.
//
// An authorization check that found no claims used to read that as "auth is
// disabled" and allow. A request that reached the check without passing the
// base handler carried no claims either -- gRPC on a plaintext TCP entrypoint
// did -- so the management API answered anyone who could reach the port. No
// claims now means nobody, unless the base handler said nobody is needed.
func AuthNotRequired(ctx context.Context) bool {
	v, _ := ctx.Value(authNotRequiredKey{}).(bool)
	return v
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
	if claims == nil {
		return make(map[string]any)
	}
	if m, ok := claims.(map[string]any); ok {
		return m
	}
	if m, ok := claims.(interface{ ToMap() map[string]any }); ok {
		return m.ToMap()
	}

	// Use reflection for named map types (e.g., jwt.MapClaims)
	v := reflect.ValueOf(claims)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() == reflect.Map {
		m := make(map[string]any)
		for _, key := range v.MapKeys() {
			if k, ok := key.Interface().(string); ok {
				m[k] = v.MapIndex(key).Interface()
			}
		}
		return m
	}

	return make(map[string]any)
}
