package api

import (
	"context"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
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
	Invalidator        proxy.Invalidator
	TLSManager         gtls.TLSManager
	RouteStatsProvider RouteStatsProvider
	EbpfManager        ebpf.Manager
	WafUpdater         *middleware.WAFUpdater
	IPReputation       *IPReputationStore
	ClamAVManager      *security.ClamAVManager
}

// GetGlobals returns the global config store for REST handlers.
func (s *ApiService) GetGlobals() config.GlobalConfigStore {
	return s.Globals
}

// GetTLSManager returns the TLS manager.
func (s *ApiService) GetTLSManager() gtls.TLSManager {
	return s.TLSManager
}

// GetEbpfManager returns the eBPF manager.
func (s *ApiService) GetEbpfManager() ebpf.Manager {
	return s.EbpfManager
}

// GetClamAVStatus returns the ClamAV installation status.
func (s *ApiService) GetClamAVStatus(ctx context.Context) bool {
	if s.ClamAVManager == nil {
		return false
	}
	return s.ClamAVManager.IsInstalled(ctx)
}

// NewApiService creates an ApiService from config (Factory pattern).
func NewApiService(cfg ApiServiceConfig) *ApiService {
	s := &ApiService{
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
		EbpfManager:        cfg.EbpfManager,
		WafUpdater:         cfg.WafUpdater,
		ClamAVManager:      cfg.ClamAVManager,
	}

	if cfg.Globals != nil {
		if gc := cfg.Globals.Get(context.Background()); gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.IpReputation != nil {
			s.IPReputation = NewIPReputationStore(gc.SecurityAdvanced.IpReputation)
			s.IPReputation.Start(context.Background())
		}
	}

	return s
}
