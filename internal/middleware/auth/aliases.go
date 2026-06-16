package auth

import "github.com/gsoultan/gateon/internal/middleware/kind"

// Middleware is the shared HTTP middleware type defined in the cycle-free leaf
// package internal/middleware/kind (ADR-0002). Aliasing it here lets the auth
// subpackage return middleware without importing the parent package middleware,
// which would create an import cycle.
type Middleware = kind.Middleware

// Shared request predicates from the kind leaf package, re-exported so the auth
// handlers can use them without importing kind throughout every file.
var (
	IsCorsPreflight   = kind.IsCorsPreflight
	GetRouteName      = kind.GetRouteName
	ShouldSkipMetrics = kind.ShouldSkipMetrics
)
