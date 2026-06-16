package auth

import (
	"fmt"

	"aidanwoods.dev/go-paseto"
)

// PasetoVerifier implements TokenVerifier for PASETO v4 local (symmetric) tokens.
type PasetoVerifier struct {
	symmetric paseto.V4SymmetricKey
}

// NewPasetoVerifier creates a verifier for PASETO v4 local (symmetric) tokens.
// The secret must be at least 32 bytes for XChaCha20-Poly1305.
func NewPasetoVerifier(secret string) (*PasetoVerifier, error) {
	keyBytes := []byte(secret)
	if len(keyBytes) < 32 {
		return nil, fmt.Errorf("paseto secret must be at least 32 bytes for v4 local")
	}
	key, err := paseto.V4SymmetricKeyFromBytes(keyBytes[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create PASETO v4 key: %w", err)
	}
	return &PasetoVerifier{
		symmetric: key,
	}, nil
}

// VerifyToken implements TokenVerifier.
func (v *PasetoVerifier) VerifyToken(token string) (any, error) {
	parser := paseto.NewParser()
	parsedToken, err := parser.ParseV4Local(v.symmetric, token, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	m := make(map[string]any)
	if val, err := parsedToken.GetSubject(); err == nil {
		m["sub"] = val
	}
	if val, err := parsedToken.GetIssuer(); err == nil {
		m["iss"] = val
	}
	if val, err := parsedToken.GetAudience(); err == nil {
		m["aud"] = val
	}
	if jti, err := parsedToken.GetString("jti"); err == nil {
		m["jti"] = jti
	}
	if exp, err := parsedToken.GetExpiration(); err == nil {
		m["exp"] = exp
	}
	if iat, err := parsedToken.GetIssuedAt(); err == nil {
		m["iat"] = iat
	}
	if nbf, err := parsedToken.GetNotBefore(); err == nil {
		m["nbf"] = nbf
	}

	// Add custom claims if any
	for k, val := range parsedToken.Claims() {
		if _, ok := m[k]; !ok {
			m[k] = val
		}
	}

	return m, nil
}
