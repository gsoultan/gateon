package api

import (
	"context"
	"time"

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

// Close closes the ApiService resources.
func (s *ApiService) Close() error {
	if s.Auth != nil {
		return s.Auth.Close()
	}
	return nil
}

func (s *ApiService) InstallClamav(ctx context.Context, req *gateonv1.InstallClamavRequest) (*gateonv1.InstallClamavResponse, error) {
	if s.ClamAVManager == nil {
		return &gateonv1.InstallClamavResponse{Success: false, Message: "ClamAV manager not initialized"}, nil
	}

	// Update global config with the new installation mode
	gc := s.Globals.Get(ctx)
	if gc.Waf == nil {
		gc.Waf = &gateonv1.WafConfig{}
	}
	if gc.Waf.Clamav == nil {
		gc.Waf.Clamav = &gateonv1.ClamavConfig{}
	}
	gc.Waf.Clamav.InstallationMode = req.Mode
	if err := s.Globals.Update(ctx, gc); err != nil {
		return &gateonv1.InstallClamavResponse{Success: false, Message: "Failed to update configuration: " + err.Error()}, nil
	}

	// Also update the manager's config directly to ensure it has the latest mode
	// Note: In security.NewClamAVManager(gc.Waf.Clamav), it's a pointer,
	// but if s.Globals.Update replaced the entire gc, we might need to be careful.
	// However, s.Globals.Get returns the pointer to r.config.
	// So updating gc.Waf.Clamav.InstallationMode above already updated it if it's the same pointer.

	if err := s.ClamAVManager.EnsureInstalled(ctx); err != nil {
		return &gateonv1.InstallClamavResponse{Success: false, Message: "Installation failed: " + err.Error()}, nil
	}

	return &gateonv1.InstallClamavResponse{Success: true, Message: "Installation started successfully"}, nil
}

func (s *ApiService) RunDeepScan(ctx context.Context, _ *gateonv1.RunDeepScanRequest) (*gateonv1.RunDeepScanResponse, error) {
	if s.ClamAVManager == nil {
		return &gateonv1.RunDeepScanResponse{Success: false, Message: "ClamAV manager not initialized"}, nil
	}

	if !s.ClamAVManager.IsInstalled(ctx) {
		return &gateonv1.RunDeepScanResponse{Success: false, Message: "ClamAV is not installed"}, nil
	}

	status := s.ClamAVManager.GetScanStatus()
	if !status.IsRunning {
		// Run scan in background as it can take a long time
		go s.ClamAVManager.RunFullScan(context.Background())
		// Refresh status to show it's now running
		status = s.ClamAVManager.GetScanStatus()
	}

	return &gateonv1.RunDeepScanResponse{
		Success: true,
		Message: "Deep scan operation processed",
		Status: &gateonv1.DeepScanStatus{
			IsRunning:  status.IsRunning,
			LastScan:   status.LastScan.Format(time.RFC3339),
			LastError:  status.LastError,
			LastResult: status.LastResult,
		},
	}, nil
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
