package handlers

import (
	"time"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/domain"
)

// Deps holds dependencies for REST API handlers (avoids importing server package).
type Deps struct {
	RouteService     domain.RouteService
	ServiceService   domain.ServiceService
	EpService        domain.EntryPointService
	MwService        domain.MiddlewareService
	TLSOptService    domain.TLSOptionService
	AuthManager      auth.Service
	Version          string
	StartTime        time.Time
}
