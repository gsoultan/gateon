package api

import (
	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
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
}
