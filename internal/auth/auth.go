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
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked due to multiple failed attempts; please try again later")
)

const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)
