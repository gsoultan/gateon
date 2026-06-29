package api

import (
	"context"

	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) GetGlobalConfig(ctx context.Context, _ *gateonv1.GetGlobalConfigRequest) (*gateonv1.GetGlobalConfigResponse, error) {
	if s.Globals == nil {
		return &gateonv1.GetGlobalConfigResponse{Config: &gateonv1.GlobalConfig{}}, nil
	}
	return &gateonv1.GetGlobalConfigResponse{Config: s.Globals.Get(ctx)}, nil
}

func (s *ApiService) UpdateGlobalConfig(ctx context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
	if s.Globals == nil || req == nil || req.Config == nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, nil
	}

	// If audit signing is enabled with no key, generate a random one BEFORE
	// persisting so it is saved to disk (chain stays verifiable across restarts)
	// and returned to the UI on the next GetGlobalConfig.
	if a := req.Config.Audit; a != nil && a.SignEntries && a.SignatureKey == "" {
		a.SignatureKey = audit.GenerateSignatureKey()
	}

	if err := s.Globals.Update(ctx, req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, err
	}

	// Trigger reconfigurations
	if req.Config.Alerting != nil {
		alerting.UpdateConfig(req.Config.Alerting, s.EbpfManager)
	}
	if req.Config.Audit != nil {
		audit.UpdateConfig(req.Config.Audit)
	}
	if req.Config.SecurityAdvanced != nil && req.Config.SecurityAdvanced.IpReputation != nil && s.IPReputation != nil {
		s.IPReputation.Reconfigure(req.Config.SecurityAdvanced.IpReputation)
	}

	// Update telemetry retention if log config is present
	if req.Config.Log != nil {
		l := req.Config.Log
		telemetry.ConfigureGranularRetention(
			int(l.PathStatsRetentionDays),
			int(l.AccessLogRetentionDays),
			int(l.SecurityThreatRetentionDays),
			int(l.AuditLogRetentionDays),
		)
	}

	// Invalidate cache if needed
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool { return true })
		if req.Config.Tls != nil {
			s.Invalidator.InvalidateTLS()
		}
	}

	// Update eBPF Port Knocking sequence
	if s.EbpfManager != nil && req.Config.Ebpf != nil {
		s.EbpfManager.SetPortKnockingSequence(req.Config.Ebpf.KnockingSequence)
	}

	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}
