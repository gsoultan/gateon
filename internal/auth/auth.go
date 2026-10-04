// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"time"

	"github.com/gsoultan/gateon/internal/auth/admission"
)

// Roles defined for RBAC
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrAccountLocked          = errors.New("account locked due to multiple failed attempts; please try again later")
	ErrAccountDisabled        = errors.New("account is disabled; contact an administrator")
	ErrTwoFactorRequired      = errors.New("two-factor authentication required")
	ErrTwoFactorSetupRequired = errors.New("two-factor authentication setup required")
	ErrInvalidTwoFactorCode   = errors.New("invalid two-factor authentication code")

	// ErrUsernameTaken refuses a create, or a rename, under a username another
	// account already has. Nothing was written.
	ErrUsernameTaken = errors.New("a user with that username already exists")

	// ErrBusy refuses a password check, before any hash, because as many are
	// running as the gate allows (ADR 0053). It is the caller's to retry, and
	// is answered as 429 / ResourceExhausted.
	ErrBusy = admission.ErrBusy
)

// signedInHashWait is how long work a signed-in caller asked for -- a
// password change, a 2FA enrolment or recovery code, an account saved with a
// password -- waits for a hash slot before it is refused as busy. Anonymous
// sign-in attempts never wait.
const signedInHashWait = 2 * time.Second

const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)
