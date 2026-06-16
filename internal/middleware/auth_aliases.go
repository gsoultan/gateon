package middleware

import "github.com/gsoultan/gateon/internal/middleware/auth"

// The authentication / authorization middlewares now live in the cohesive
// subpackage internal/middleware/auth (ADR-0002, Session 7). The transparent
// aliases below keep package middleware (the factory dispatch, policy/bot
// helpers and the package tests) and all external callers — which reference
// middleware.JWTValidator, middleware.PasetoAuth, middleware.UserContextKey,
// etc. — compiling unchanged while the per-concern split proceeds.

// Auth configuration and validator types.
type (
	AuthBaseConfig               = auth.AuthBaseConfig
	JWTConfig                    = auth.JWTConfig
	JWTValidator                 = auth.JWTValidator
	APIKeyValidator              = auth.APIKeyValidator
	TokenVerifier                = auth.TokenVerifier
	HMACConfig                   = auth.HMACConfig
	ForwardAuthConfig            = auth.ForwardAuthConfig
	OIDCProxyConfig              = auth.OIDCProxyConfig
	OAuth2IntrospectionConfig    = auth.OAuth2IntrospectionConfig
	OAuth2IntrospectionValidator = auth.OAuth2IntrospectionValidator
	PasetoVerifier               = auth.PasetoVerifier
	APIKeyStore                  = auth.APIKeyStore
	MemoryAPIKeyStore            = auth.MemoryAPIKeyStore
	RedisAPIKeyStore             = auth.RedisAPIKeyStore
	RevocationStore              = auth.RevocationStore
	RedisRevocationStore         = auth.RedisRevocationStore
)

// Request-context keys set by the auth middlewares.
const (
	UserContextKey     = auth.UserContextKey
	TenantIDContextKey = auth.TenantIDContextKey
)

// Auth constructors, middleware factories, and helpers.
var (
	NewJWTValidator                 = auth.NewJWTValidator
	NewAPIKeyValidator              = auth.NewAPIKeyValidator
	NewOAuth2IntrospectionValidator = auth.NewOAuth2IntrospectionValidator
	NewOIDCValidator                = auth.NewOIDCValidator
	NewPasetoVerifier               = auth.NewPasetoVerifier
	NewMemoryAPIKeyStore            = auth.NewMemoryAPIKeyStore
	NewRedisAPIKeyStore             = auth.NewRedisAPIKeyStore
	NewRedisRevocationStore         = auth.NewRedisRevocationStore

	PasetoAuth               = auth.PasetoAuth
	BasicAuth                = auth.BasicAuth
	BasicAuthWithRealm       = auth.BasicAuthWithRealm
	BasicAuthWithConfig      = auth.BasicAuthWithConfig
	BasicAuthUsers           = auth.BasicAuthUsers
	BasicAuthUsersWithConfig = auth.BasicAuthUsersWithConfig
	ForwardAuth              = auth.ForwardAuth
	HMAC                     = auth.HMAC
	OIDCProxy                = auth.OIDCProxy

	ExtractToken        = auth.ExtractToken
	SetSessionCookie    = auth.SetSessionCookie
	ClearSessionCookie  = auth.ClearSessionCookie
	InjectContext       = auth.InjectContext
	ToMap               = auth.ToMap
	ConstantTimeCompare = auth.ConstantTimeCompare
)
