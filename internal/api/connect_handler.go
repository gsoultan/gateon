// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package api

import (
	"context"

	"connectrpc.com/connect"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// ConnectHandler wraps ApiService to provide ConnectRPC compatibility.
// It implements gateonv1connect.ApiServiceHandler.
type ConnectHandler struct {
	gateonv1connect.UnimplementedApiServiceHandler
	s *ApiService
}

func NewConnectHandler(s *ApiService) gateonv1connect.ApiServiceHandler {
	return &ConnectHandler{s: s}
}

// --- Common ---

func (h *ConnectHandler) GetStatus(ctx context.Context, req *connect.Request[gateonv1.GetStatusRequest]) (*connect.Response[gateonv1.GetStatusResponse], error) {
	res, err := h.s.GetStatus(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// --- Audit Logs ---

func (h *ConnectHandler) ListAuditLogs(ctx context.Context, req *connect.Request[gateonv1.ListAuditLogsRequest]) (*connect.Response[gateonv1.ListAuditLogsResponse], error) {
	res, err := h.s.ListAuditLogs(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ListAuditArchives(ctx context.Context, req *connect.Request[gateonv1.ListAuditArchivesRequest]) (*connect.Response[gateonv1.ListAuditArchivesResponse], error) {
	res, err := h.s.ListAuditArchives(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) GetAuditArchive(ctx context.Context, req *connect.Request[gateonv1.GetAuditArchiveRequest]) (*connect.Response[gateonv1.GetAuditArchiveResponse], error) {
	res, err := h.s.GetAuditArchive(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// --- Diagnostics & Threats ---

func (h *ConnectHandler) GetDiagnostics(ctx context.Context, req *connect.Request[gateonv1.GetDiagnosticsRequest]) (*connect.Response[gateonv1.GetDiagnosticsResponse], error) {
	res, err := h.s.GetDiagnostics(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ListSecurityThreats(ctx context.Context, req *connect.Request[gateonv1.ListSecurityThreatsRequest]) (*connect.Response[gateonv1.ListSecurityThreatsResponse], error) {
	res, err := h.s.ListSecurityThreats(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) GetSecurityThreat(ctx context.Context, req *connect.Request[gateonv1.GetSecurityThreatRequest]) (*connect.Response[gateonv1.GetSecurityThreatResponse], error) {
	res, err := h.s.GetSecurityThreat(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) MitigateThreat(ctx context.Context, req *connect.Request[gateonv1.MitigateThreatRequest]) (*connect.Response[gateonv1.MitigateThreatResponse], error) {
	res, err := h.s.MitigateThreat(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) RemoveMitigatedThreat(ctx context.Context, req *connect.Request[gateonv1.RemoveMitigatedThreatRequest]) (*connect.Response[gateonv1.RemoveMitigatedThreatResponse], error) {
	res, err := h.s.RemoveMitigatedThreat(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ListReputations(ctx context.Context, req *connect.Request[gateonv1.ListReputationsRequest]) (*connect.Response[gateonv1.ListReputationsResponse], error) {
	res, err := h.s.ListReputations(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ApplyRecommendation(ctx context.Context, req *connect.Request[gateonv1.ApplyRecommendationRequest]) (*connect.Response[gateonv1.ApplyRecommendationResponse], error) {
	res, err := h.s.ApplyRecommendation(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// --- Traces ---

func (h *ConnectHandler) ListTraces(ctx context.Context, req *connect.Request[gateonv1.ListTracesRequest]) (*connect.Response[gateonv1.ListTracesResponse], error) {
	res, err := h.s.ListTraces(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) GetTrace(ctx context.Context, req *connect.Request[gateonv1.GetTraceRequest]) (*connect.Response[gateonv1.GetTraceResponse], error) {
	res, err := h.s.GetTrace(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}
