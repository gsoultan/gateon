package handlers

import (
	"time"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/domain"
	"github.com/gateon/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route. Nil if route not found.
type RouteStatsProvider func(routeID string) []proxy.TargetStats

// Deps holds dependencies for REST API handlers (avoids importing server package).
type Deps struct {
	RouteService       domain.RouteService
	ServiceService     domain.ServiceService
	EpService          domain.EntryPointService
	MwService          domain.MiddlewareService
	TLSOptService      domain.TLSOptionService
	AuthManager        auth.Service
	Version            string
	StartTime          time.Time
	RouteStatsProvider RouteStatsProvider
}
