package auth

import (
	"errors"
	"time"
)

type Claims struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	Audience   string    `json:"aud,omitzero"`
	Issuer     string    `json:"iss,omitzero"`
	Jti        string    `json:"jti,omitzero"`
	Subject    string    `json:"sub,omitzero"`
	Expiration time.Time `json:"exp,omitzero"`
	IssuedAt   time.Time `json:"iat,omitzero"`
	NotBefore  time.Time `json:"nbf,omitzero"`
}

func (c *Claims) Validate() error {
	now := time.Now()
	if !c.Expiration.IsZero() && now.After(c.Expiration) {
		return errors.New("token expired")
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore) {
		return errors.New("token not yet valid")
	}
	return nil
}

func (c *Claims) ToMap() map[string]any {
	return map[string]any{
		"id":       c.ID,
		"username": c.Username,
		"role":     c.Role,
		"roles":    []string{c.Role},
		"aud":      c.Audience,
		"iss":      c.Issuer,
		"jti":      c.Jti,
		"sub":      c.Subject,
		"exp":      c.Expiration,
		"iat":      c.IssuedAt,
		"nbf":      c.NotBefore,
	}
}
