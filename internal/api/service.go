package api

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ApiService implements gateonv1.ApiServiceServer.
type ApiService struct {
	gateonv1.UnimplementedApiServiceServer
	Version            string
	Routes             config.RouteStore
	Services           config.ServiceStore
	Globals            config.GlobalConfigStore
	EntryPoints        config.EntryPointStore
	Middlewares        config.MiddlewareStore
	TLSOptions         config.TLSOptionStore
	Auth               auth.Service
	Invalidator        domain.ProxyInvalidator
	TLSManager         gtls.TLSManager
	RouteStatsProvider RouteStatsProvider
}

// GetGlobals returns the global config store for REST handlers.
func (s *ApiService) GetGlobals() config.GlobalConfigStore {
	return s.Globals
}

// GetTLSManager returns the TLS manager.
func (s *ApiService) GetTLSManager() gtls.TLSManager {
	return s.TLSManager
}

// NewApiService creates an ApiService from config (Factory pattern).
func NewApiService(cfg ApiServiceConfig) *ApiService {
	return &ApiService{
		Version:            cfg.Version,
		Routes:             cfg.Routes,
		Services:           cfg.Services,
		Globals:            cfg.Globals,
		EntryPoints:        cfg.EntryPoints,
		Middlewares:        cfg.Middlewares,
		TLSOptions:         cfg.TLSOptions,
		Auth:               cfg.Auth,
		Invalidator:        cfg.Invalidator,
		TLSManager:         cfg.TLSManager,
		RouteStatsProvider: cfg.RouteStatsProvider,
	}
}
