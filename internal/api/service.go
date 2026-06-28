package api

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/reputation"
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
	IPReputation       *reputation.IPReputationStore
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

	// Apply the requested mode to the manager directly so it does not depend on
	// the config-change supervisor wiring being present (e.g. in tests). This is
	// idempotent with the supervisor's own reconcile.
	s.ClamAVManager.Reconfigure(ctx, gc.Waf.Clamav)

	// Validate prerequisites synchronously so the operator gets an immediate,
	// actionable error (missing Docker, no package manager, insufficient
	// privileges) instead of a silent background failure.
	if err := s.ClamAVManager.Preflight(); err != nil {
		return &gateonv1.InstallClamavResponse{Success: false, Message: err.Error()}, nil
	}

	// The actual install (docker pull / apt install / freshclam DB download) can
	// take several minutes — far longer than an HTTP request should block. Run it
	// on a detached context so it is not cancelled when this request returns.
	go func() {
		if err := s.ClamAVManager.EnsureInstalled(context.Background()); err != nil {
			logger.L.LogError("ClamAV background installation failed", "error", err)
		}
	}()

	return &gateonv1.InstallClamavResponse{Success: true, Message: "Installation started successfully"}, nil
}

func (s *ApiService) UninstallClamav(ctx context.Context, _ *gateonv1.UninstallClamavRequest) (*gateonv1.UninstallClamavResponse, error) {
	if s.ClamAVManager == nil {
		return &gateonv1.UninstallClamavResponse{Success: false, Message: "ClamAV manager not initialized"}, nil
	}

	// Validate prerequisites synchronously so the operator gets an immediate,
	// actionable error (missing Docker, no package manager, insufficient
	// privileges) instead of a silent background failure.
	if err := s.ClamAVManager.PreflightUninstall(); err != nil {
		return &gateonv1.UninstallClamavResponse{Success: false, Message: err.Error()}, nil
	}

	// Removal (docker rm / apt remove) can take a while, so detach it from the
	// request lifecycle on a background context just like installation.
	go func() {
		if err := s.ClamAVManager.Uninstall(context.Background()); err != nil {
			logger.L.LogError("ClamAV background uninstallation failed", "error", err)
		}
	}()

	return &gateonv1.UninstallClamavResponse{Success: true, Message: "Uninstallation started successfully"}, nil
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

	if cfg.IPReputation != nil {
		s.IPReputation = cfg.IPReputation
	} else if cfg.Globals != nil {
		if gc := cfg.Globals.Get(context.Background()); gc != nil && gc.SecurityAdvanced != nil && gc.SecurityAdvanced.IpReputation != nil {
			s.IPReputation = reputation.NewIPReputationStore(gc.SecurityAdvanced.IpReputation)
			s.IPReputation.Start(context.Background())
		}
	}

	return s
}
