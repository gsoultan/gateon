// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (h *ConnectHandler) VerifyAuditChain(ctx context.Context, req *connect.Request[gateonv1.VerifyAuditChainRequest]) (*connect.Response[gateonv1.VerifyAuditChainResponse], error) {
	res, err := h.s.VerifyAuditChain(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// --- Scrape credentials (ADR 0050) ---

func (h *ConnectHandler) ListApiTokens(ctx context.Context, req *connect.Request[gateonv1.ListApiTokensRequest]) (*connect.Response[gateonv1.ListApiTokensResponse], error) {
	res, err := h.s.ListApiTokens(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) CreateApiToken(ctx context.Context, req *connect.Request[gateonv1.CreateApiTokenRequest]) (*connect.Response[gateonv1.CreateApiTokenResponse], error) {
	res, err := h.s.CreateApiToken(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) RevokeApiToken(ctx context.Context, req *connect.Request[gateonv1.RevokeApiTokenRequest]) (*connect.Response[gateonv1.RevokeApiTokenResponse], error) {
	res, err := h.s.RevokeApiToken(ctx, req.Msg)
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

// --- Called by the dashboard over Connect ---
//
// These five existed on ApiService, and the dashboard's Connect client calls
// them, but nothing here forwarded them, so the embedded
// UnimplementedApiServiceHandler answered: the first-run setup wizard could not
// create the administrator, and the trace visualizer, the CORS validator and
// the Cloudflare trust-list import failed with "unimplemented". Authorization
// is the RBAC interceptor's, which already maps each procedure.

func (h *ConnectHandler) Setup(ctx context.Context, req *connect.Request[gateonv1.SetupRequest]) (*connect.Response[gateonv1.SetupResponse], error) {
	res, err := h.s.Setup(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) TraceRoute(ctx context.Context, req *connect.Request[gateonv1.TraceRouteRequest]) (*connect.Response[gateonv1.TraceRouteResponse], error) {
	res, err := h.s.TraceRoute(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ValidateCORS(ctx context.Context, req *connect.Request[gateonv1.ValidateCORSRequest]) (*connect.Response[gateonv1.ValidateCORSResponse], error) {
	res, err := h.s.ValidateCORS(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) GetCloudflareIPs(ctx context.Context, req *connect.Request[gateonv1.GetCloudflareIPsRequest]) (*connect.Response[gateonv1.GetCloudflareIPsResponse], error) {
	res, err := h.s.GetCloudflareIPs(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) RunDeepScan(ctx context.Context, req *connect.Request[gateonv1.RunDeepScanRequest]) (*connect.Response[gateonv1.RunDeepScanResponse], error) {
	res, err := h.s.RunDeepScan(ctx, req.Msg)
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

func (h *ConnectHandler) QueryTraces(ctx context.Context, req *connect.Request[gateonv1.QueryTracesRequest]) (*connect.Response[gateonv1.QueryTracesResponse], error) {
	res, err := h.s.QueryTraces(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h *ConnectHandler) ListTraceArchives(ctx context.Context, req *connect.Request[gateonv1.ListTraceArchivesRequest]) (*connect.Response[gateonv1.ListTraceArchivesResponse], error) {
	res, err := h.s.ListTraceArchives(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

// StatusInterceptor carries ApiService's gRPC statuses across Connect.
// ApiService answers in grpc-go statuses, which connect-go does not recognise:
// it sends any error it did not make itself as Unknown, over HTTP 500, with the
// whole "rpc error: code = NotFound desc = trace not found" as its message. A
// missing trace then read as a failure to retry, a refused request as a string
// of internals, and a permission refusal not as one. Each status keeps its code
// and its message instead; the two code spaces share their numbering.
func StatusInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			res, err := next(ctx, req)
			if err != nil {
				err = connectCode(err)
			}
			return res, err
		}
	}
}

// connectCode turns a gRPC status ApiService returned into the Connect error
// with its code and message. Anything else passes through unchanged: an error
// that is already a Connect error, one with no status, and -- deliberately --
// a status found only by unwrapping. ApiService wraps what the backends it
// probes answer (gRPC discovery asks a backend for its reflection service), and
// a backend's Unauthenticated, carried across, would read to the dashboard as
// its own session expiring and sign the administrator out. For the same
// reason Unauthenticated is never converted: ApiService does not return it,
// and a session that has really expired is refused before RBAC, as HTTP 401.
func connectCode(err error) error {
	own, ok := err.(interface{ GRPCStatus() *status.Status }) //nolint:errorlint // unwrapping is what this must not do; see above
	if !ok {
		return err
	}
	st := own.GRPCStatus()
	switch st.Code() {
	case codes.OK, codes.Unknown, codes.Unauthenticated:
		return err
	}
	return connect.NewError(connect.Code(st.Code()), errors.New(st.Message()))
}
