package auth

import (
	"fmt"

	"aidanwoods.dev/go-paseto"
)

// PasetoVerifier implements TokenVerifier for PASETO v4 local (symmetric) tokens.
type PasetoVerifier struct {
	symmetric paseto.V4SymmetricKey
	parser    paseto.Parser
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
		parser:    paseto.NewParser(),
	}, nil
}

// VerifyToken implements TokenVerifier.
func (v *PasetoVerifier) VerifyToken(token string) (any, error) {
	parsedToken, err := v.parser.ParseV4Local(v.symmetric, token, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return parsedToken.Claims(), nil
}
