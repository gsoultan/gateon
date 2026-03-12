package handlers

import (
	"time"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// Deps holds dependencies for REST API handlers (avoids importing server package).
type Deps struct {
	RouteReg              *config.RouteRegistry
	ServiceReg             *config.ServiceRegistry
	EpReg                  *config.EntryPointRegistry
	MwReg                  *config.MiddlewareRegistry
	TLSOptReg              *config.TLSOptionRegistry
	InvalidateRouteProxy   func(string)
	InvalidateRouteProxies  func(func(*gateonv1.Route) bool)
	AuthManager            *auth.Manager
	Version                string
	StartTime              time.Time
}
