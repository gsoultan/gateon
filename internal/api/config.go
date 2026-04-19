package api

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/tls"
)

// ApiServiceConfig holds dependencies for ApiService (Factory pattern).
type ApiServiceConfig struct {
	Version     string
	Routes      config.RouteStore
	Services    config.ServiceStore
	Globals     config.GlobalConfigStore
	EntryPoints config.EntryPointStore
	Middlewares config.MiddlewareStore
	TLSOptions  config.TLSOptionStore
	Auth        auth.Service
	Invalidator domain.ProxyInvalidator
	TLSManager  tls.TLSManager
}
