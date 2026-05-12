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
	}

	// Update eBPF Port Knocking sequence
	if s.EbpfManager != nil && req.Config.Ebpf != nil {
		s.EbpfManager.SetPortKnockingSequence(req.Config.Ebpf.KnockingSequence)
	}

	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}
