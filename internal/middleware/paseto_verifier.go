package middleware

import (
	"fmt"

	"github.com/o1egl/paseto/v2"
)

// PasetoVerifier implements TokenVerifier for PASETO v2 local (symmetric) tokens.
type PasetoVerifier struct {
	v2        *paseto.V2
	symmetric []byte
}

// NewPasetoVerifier creates a verifier for PASETO v2 local (symmetric) tokens.
// The secret must be at least 32 bytes for XChaCha20-Poly1305; excess bytes are truncated.
func NewPasetoVerifier(secret string) (*PasetoVerifier, error) {
	key := []byte(secret)
	if len(key) < 32 {
		return nil, fmt.Errorf("paseto secret must be at least 32 bytes for v2 local")
	}
	if len(key) > 32 {
		key = key[:32]
	}
	return &PasetoVerifier{
		v2:        paseto.NewV2(),
		symmetric: key,
	}, nil
}

// VerifyToken implements TokenVerifier.
func (v *PasetoVerifier) VerifyToken(token string) (any, error) {
	var claims paseto.JSONToken
	if err := v.v2.Decrypt(token, v.symmetric, &claims, nil); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	m := make(map[string]any)
	m["sub"] = claims.Subject
	m["iss"] = claims.Issuer
	m["aud"] = claims.Audience
	m["jti"] = claims.Jti
	m["exp"] = claims.Expiration
	m["iat"] = claims.IssuedAt
	m["nbf"] = claims.NotBefore
	return m, nil
}
