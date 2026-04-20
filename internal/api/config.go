package api

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/proxy"
)

// RouteStatsProvider returns target stats for a route.
type RouteStatsProvider func(routeID string) []proxy.TargetStats

// ApiServiceConfig holds dependencies for ApiService (Factory pattern).
type ApiServiceConfig struct {
	Version            string
	Routes             config.RouteStore
	Services           config.ServiceStore
	Globals            config.GlobalConfigStore
	EntryPoints        config.EntryPointStore
	Middlewares        config.MiddlewareStore
	TLSOptions         config.TLSOptionStore
	Auth               auth.Service
	Invalidator        domain.ProxyInvalidator
	TLSManager         tls.TLSManager
	RouteStatsProvider RouteStatsProvider
}
