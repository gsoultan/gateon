package auth

import (
	"errors"
	"time"
)

// Roles defined for RBAC
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrAccountLocked        = errors.New("account locked due to multiple failed attempts; please try again later")
	ErrTwoFactorRequired    = errors.New("two-factor authentication required")
	ErrInvalidTwoFactorCode = errors.New("invalid two-factor authentication code")
)

const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)
