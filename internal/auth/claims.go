// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/subtle"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
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

	// SessionBinding ties the token to the account state it was issued
	// against. It is deliberately absent from ToMap: it is an internal
	// revocation check, not an identity claim, and middleware copies mapped
	// claims into upstream request headers.
	SessionBinding string `json:"-"`
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

// PurposeClaim names what a token minted under the session key is for. A
// session carries none; anything else carries one, and VerifyToken refuses a
// token that does, so no other kind of token is ever a session.
const PurposeClaim = "purpose"

// purposeTwoFactorChallenge marks a two-factor challenge. See ADR 0039.
const purposeTwoFactorChallenge = "2fa-challenge"

// ChallengeLifetime is how long a two-factor challenge stays valid: long
// enough to find an authenticator, or to scan a QR code and type the first
// code, and short enough that one carried off is little use.
const ChallengeLifetime = 5 * time.Minute

// challengeImplicit is bound into every challenge as PASETO's implicit
// assertion. A token encrypted with it does not decrypt without it, so neither
// VerifyToken nor a route's PASETO middleware configured with the same secret
// can even read a challenge, whatever claims it carries -- and a session,
// encrypted without it, does not decrypt as a challenge. The purpose claim says
// the same thing in the token's own words; this makes it a property of the
// encryption rather than of a check someone has to remember to make.
var challengeImplicit = []byte("gateon/v1/2fa-challenge")

// ErrInvalidChallenge refuses a second sign-in step that does not carry proof
// of the first: no challenge, an expired one, one for another account, one the
// account has since voided, or something that is not a challenge at all. One
// error for all of them, so a caller learns nothing about which.
var ErrInvalidChallenge = errors.New("the sign-in step has expired or is not valid; sign in again")

// errNotASession refuses a token with a purpose, which a session never has.
var errNotASession = errors.New("not a session token")

// SecondStepError is Authenticate's answer to a correct password when a second
// factor is still owed. It wraps ErrTwoFactorRequired or
// ErrTwoFactorSetupRequired, so errors.Is reads it as before, and carries the
// challenge the second step requires. Error() does not include the challenge,
// so logging the error never writes one down.
type SecondStepError struct {
	// Err is ErrTwoFactorRequired or ErrTwoFactorSetupRequired.
	Err error
	// Challenge proves the password step; see Manager.Verify2FA.
	Challenge string
}

func (e *SecondStepError) Error() string { return e.Err.Error() }

func (e *SecondStepError) Unwrap() error { return e.Err }

// ChallengeFrom returns the two-factor challenge err carries, or "".
func ChallengeFrom(err error) string {
	var step *SecondStepError
	if errors.As(err, &step) {
		return step.Challenge
	}
	return ""
}

// issueChallenge mints the proof that account id's password was presented at
// now: a token under the session key that only Verify2FA accepts, naming id,
// expiring ChallengeLifetime later, and bound to the account's state the way a
// session is, so a password, role or disabled change, or a sign-out, voids it.
// It is not single-use: the code it is spent with is the secret, and its holder
// already had the password.
func (m *Manager) issueChallenge(id string, now time.Time) (string, error) {
	return m.issueChallengeFor(id, now, stagedFactor{})
}

// Claims a re-enrolment challenge carries: the replacement factor, until a
// code from it is confirmed. See stagedFactor.
const (
	stagedSecretClaim = "staged_secret"
	stagedCodesClaim  = "staged_codes"
)

// stagedFactor is a replacement second factor for an account that already has
// one, carried in the re-enrolment challenge rather than written to the
// account: the encrypted TOTP secret and the hashed recovery codes, exactly as
// they will be stored once a code from the new authenticator is confirmed.
//
// Re-enrolment used to store the new secret with two_factor_enabled = false
// before any code was checked, so abandoning it left the account signing in
// with the password alone, and its working authenticator and recovery codes
// dead. Nothing is written now until Verify2FA confirms the new one. The
// challenge is encrypted under the session key, so the secret is no more
// readable in it than in the database, and it dies with the challenge.
type stagedFactor struct {
	encSecret   string
	hashedCodes string
}

func (m *Manager) issueChallengeFor(id string, now time.Time, staged stagedFactor) (string, error) {
	binding, err := m.currentBinding(id)
	if err != nil {
		return "", err
	}
	t := paseto.NewToken()
	if staged.encSecret != "" {
		t.SetString(stagedSecretClaim, staged.encSecret)
		t.SetString(stagedCodesClaim, staged.hashedCodes)
	}
	t.SetIssuedAt(now)
	t.SetNotBefore(now)
	t.SetExpiration(now.Add(ChallengeLifetime))
	t.SetSubject(id)
	t.SetString(PurposeClaim, purposeTwoFactorChallenge)
	t.SetString(SessionBindingClaim, binding)
	return t.V4Encrypt(m.keys.Load().sign, challengeImplicit), nil
}

// checkChallenge accepts challenge only if it is a live two-factor challenge
// issued for account id under the account's present state. Every refusal is
// ErrInvalidChallenge.
func (m *Manager) checkChallenge(challenge, id string) error {
	_, err := m.parseChallenge(challenge, id)
	return err
}

// parseChallenge is checkChallenge, and returns the replacement factor the
// challenge stages: the zero stagedFactor when it stages none.
func (m *Manager) parseChallenge(challenge, id string) (stagedFactor, error) {
	parsed, err := m.validChallenge(challenge, id)
	if err != nil {
		return stagedFactor{}, err
	}
	enc, err := parsed.GetString(stagedSecretClaim)
	if err != nil {
		return stagedFactor{}, nil
	}
	codes, _ := parsed.GetString(stagedCodesClaim)
	return stagedFactor{encSecret: enc, hashedCodes: codes}, nil
}

func (m *Manager) validChallenge(challenge, id string) (*paseto.Token, error) {
	if challenge == "" || id == "" {
		return nil, ErrInvalidChallenge
	}
	parsed, err := m.parser.ParseV4Local(m.keys.Load().sign, challenge, challengeImplicit)
	if err != nil {
		return nil, ErrInvalidChallenge
	}
	if purpose, err := parsed.GetString(PurposeClaim); err != nil || purpose != purposeTwoFactorChallenge {
		return nil, ErrInvalidChallenge
	}
	if sub, err := parsed.GetSubject(); err != nil || subtle.ConstantTimeCompare([]byte(sub), []byte(id)) != 1 {
		return nil, ErrInvalidChallenge
	}
	if exp, err := parsed.GetExpiration(); err != nil || !time.Now().Before(exp) {
		return nil, ErrInvalidChallenge
	}
	binding, err := parsed.GetString(SessionBindingClaim)
	if err != nil || m.checkSessionBinding(id, binding) != nil {
		return nil, ErrInvalidChallenge
	}
	return parsed, nil
}
