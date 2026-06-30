package middleware

import (
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
)

// The cycle-free core middleware primitives now live in the leaf package
// internal/middleware/kind (ADR-0002, Stage 0). The transparent aliases below
// keep the rest of package middleware and all external callers (which reference
// middleware.Middleware, middleware.Chain, middleware.StatusResponseWriter, the
// context keys, etc.) compiling unchanged while the per-concern subpackages are
// migrated out in later stages.

// Core types.
type (
	Middleware            = kind.Middleware
	ContextKey            = kind.ContextKey
	SecurityHeadersConfig = kind.SecurityHeadersConfig
	StatusResponseWriter  = kind.StatusResponseWriter
	ErrorsConfig          = kind.ErrorsConfig
	RequestState          = request.RequestState
	DebugInfo             = request.DebugInfo
)

// Request-context keys.
var (
	EntryPointIDContextKey = kind.EntryPointIDContextKey
	RequestStateContextKey = request.RequestStateContextKey{}
)

const (
	RouteNameContextKey    = kind.RouteNameContextKey
	MatchedRouteContextKey = kind.MatchedRouteContextKey
	IsManagementContextKey = kind.IsManagementContextKey
	DebugInfoContextKey    = kind.DebugInfoContextKey
	FingerprintContextKey  = kind.FingerprintContextKey
	CORSHandledContextKey  = kind.CORSHandledContextKey
)

var (
	GetRequestState  = request.GetRequestState
	RequestStatePool = &request.RequestStatePool
)

// Core constructors, predicates, and the pooled status writer.
var (
	Chain                   = kind.Chain
	Recovery                = kind.Recovery
	SecurityHeaders         = kind.SecurityHeaders
	Errors                  = kind.Errors
	GetRouteName            = kind.GetRouteName
	IsInternalPath          = kind.IsInternalPath
	IsDashboardPath         = kind.IsDashboardPath
	ShouldSkipMetrics       = kind.ShouldSkipMetrics
	IsCorsPreflight         = kind.IsCorsPreflight
	GetStatusResponseWriter = kind.GetStatusResponseWriter
	PutStatusResponseWriter = kind.PutStatusResponseWriter
	RealIP                  = kind.RealIP
	GetRequestID            = kind.GetRequestID

	// getStatusString is kept as an unexported alias so internal callers
	// (e.g. standard.go) continue to compile without importing kind directly.
	getStatusString = kind.StatusString
)
