package handlers

import (
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/domain/canary"
	"github.com/gsoultan/gateon/internal/domain/entrypoint"
	"github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/domain/tls"
	"github.com/gsoultan/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route. Nil if route not found.
type RouteStatsProvider func(routeID string) []proxy.TargetStats

// Deps holds dependencies for REST API handlers (avoids importing server package).
type Deps struct {
	RouteService       route.Service
	ServiceService     service.Service
	EpService          entrypoint.Service
	MwService          middleware.Service
	TLSOptService      tls.Service
	CanaryService      canary.Service
	AuthManager        auth.Service
	Version            string
	StartTime          time.Time
	RouteStatsProvider RouteStatsProvider
	// SecurityPosture, when set, supplies the report for GET /v1/security/posture.
	SecurityPosture SecurityPostureProvider
}
