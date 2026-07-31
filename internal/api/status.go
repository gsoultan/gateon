package api

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ApiService) GetStatus(ctx context.Context, _ *gateonv1.GetStatusRequest) (*gateonv1.GetStatusResponse, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	routesCount := 0
	if s.Routes != nil {
		routesCount = len(s.Routes.List(ctx))
	}
	servicesCount := 0
	if s.Services != nil {
		servicesCount = len(s.Services.List(ctx))
	}
	entryPointsCount := 0
	if s.EntryPoints != nil {
		entryPointsCount = len(s.EntryPoints.List(ctx))
	}
	middlewaresCount := 0
	if s.Middlewares != nil {
		middlewaresCount = len(s.Middlewares.List(ctx))
	}

	stats := telemetry.GetSystemStats()

	return &gateonv1.GetStatusResponse{
		Status:              "running",
		Version:             s.Version,
		Uptime:              int64(time.Since(telemetry.GetStartTime()).Seconds()),
		MemoryUsage:         int64(m.Alloc),
		RoutesCount:         int32(routesCount),
		ServicesCount:       int32(servicesCount),
		EntryPointsCount:    int32(entryPointsCount),
		MiddlewaresCount:    int32(middlewaresCount),
		CpuUsage:            stats.CPUUsage,
		MemoryUsagePercent:  stats.MemoryUsagePercent,
		CpuCores:            int32(runtime.NumCPU()),
		MemoryTotalGb:       float64(stats.MemoryTotalBytes) / (1024 * 1024 * 1024),
		StorageUsageGb:      float64(stats.StorageUsageBytes) / (1024 * 1024 * 1024),
		StorageTotalGb:      float64(stats.StorageTotalBytes) / (1024 * 1024 * 1024),
		StorageUsagePercent: stats.StorageUsagePercent,
		ClamavInstalled:     s.ClamAVManager != nil && s.ClamAVManager.IsInstalled(ctx),
	}, nil
}

func (s *ApiService) ListTraces(ctx context.Context, req *gateonv1.ListTracesRequest) (*gateonv1.ListTracesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	traces := telemetry.GetTracesFiltered(ctx, int(req.Limit), req.Summary)
	res := make([]*gateonv1.Trace, 0, len(traces))
	for _, t := range traces {
		var reqHeaders, respHeaders map[string]string
		if !req.Summary {
			reqHeaders = telemetry.ParseHeaders(t.RequestHeaders)
			respHeaders = telemetry.ParseHeaders(t.ResponseHeaders)
		}

		res = append(res, &gateonv1.Trace{
			Id:                t.ID,
			OperationName:     t.OperationName,
			ServiceName:       t.ServiceName,
			DurationMs:        t.DurationMs,
			Timestamp:         t.Timestamp.Format(time.RFC3339Nano),
			Status:            t.Status,
			Path:              t.Path,
			SourceIp:          t.SourceIP,
			UserAgent:         t.UserAgent,
			Method:            t.Method,
			Referer:           t.Referer,
			RequestUri:        t.RequestURI,
			RequestHeaders:    reqHeaders,
			RequestBody:       t.RequestBody,
			ResponseHeaders:   respHeaders,
			ResponseBody:      t.ResponseBody,
			Ja4:               t.JA4,
			Ja4H:              t.JA4H,
			Recommendation:    t.Recommendation,
			Reputation:        t.Reputation,
			EntrypointDelayMs: t.EntrypointDelay,
			RouteDelayMs:      t.RouteDelay,
			MiddlewareDelayMs: t.MiddlewareDelay,
			ServiceDelayMs:    t.ServiceDelay,
		})
	}
	return &gateonv1.ListTracesResponse{Traces: res}, nil
}

func (s *ApiService) GetTrace(ctx context.Context, req *gateonv1.GetTraceRequest) (*gateonv1.GetTraceResponse, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "ID is required")
	}
	if req.Timestamp == "" {
		return nil, status.Error(codes.InvalidArgument, "Timestamp is required for O(1) lookup")
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid timestamp format: %v", err)
	}

	t := telemetry.GetTrace(ts, req.Id)
	if t == nil {
		return nil, status.Error(codes.NotFound, "trace not found")
	}

	reqHeaders := telemetry.ParseHeaders(t.RequestHeaders)
	respHeaders := telemetry.ParseHeaders(t.ResponseHeaders)

	return &gateonv1.GetTraceResponse{
		Trace: &gateonv1.Trace{
			Id:                t.ID,
			OperationName:     t.OperationName,
			ServiceName:       t.ServiceName,
			DurationMs:        t.DurationMs,
			Timestamp:         t.Timestamp.Format(time.RFC3339Nano),
			Status:            t.Status,
			Path:              t.Path,
			SourceIp:          t.SourceIP,
			UserAgent:         t.UserAgent,
			Method:            t.Method,
			Referer:           t.Referer,
			RequestUri:        t.RequestURI,
			RequestHeaders:    reqHeaders,
			RequestBody:       t.RequestBody,
			ResponseHeaders:   respHeaders,
			ResponseBody:      t.ResponseBody,
			Ja4:               t.JA4,
			Ja4H:              t.JA4H,
			Recommendation:    t.Recommendation,
			Reputation:        t.Reputation,
			EntrypointDelayMs: t.EntrypointDelay,
			RouteDelayMs:      t.RouteDelay,
			MiddlewareDelayMs: t.MiddlewareDelay,
			ServiceDelayMs:    t.ServiceDelay,
		},
	}, nil
}

func (s *ApiService) TraceRoute(ctx context.Context, req *gateonv1.TraceRouteRequest) (*gateonv1.TraceRouteResponse, error) {
	if req.Ip == "" {
		return nil, status.Error(codes.InvalidArgument, "IP address is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	serverIP := getPublicIP(ctx)
	hops, err := telemetry.TraceRoute(ctx, req.Ip, serverIP)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to perform traceroute: %v", err)
	}

	return &gateonv1.TraceRouteResponse{
		Hops: hops,
	}, nil
}
