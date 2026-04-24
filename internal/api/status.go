package api

import (
	"context"
	"encoding/json"
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
		Status:             "running",
		Version:            s.Version,
		Uptime:             int64(time.Since(telemetry.GetStartTime()).Seconds()),
		MemoryUsage:        int64(m.Alloc),
		RoutesCount:        int32(routesCount),
		ServicesCount:      int32(servicesCount),
		EntryPointsCount:   int32(entryPointsCount),
		MiddlewaresCount:   int32(middlewaresCount),
		CpuUsage:           stats.CPUUsage,
		MemoryUsagePercent: stats.MemoryUsagePercent,
	}, nil
}

func (s *ApiService) ListTraces(ctx context.Context, req *gateonv1.ListTracesRequest) (*gateonv1.ListTracesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	traces := telemetry.GetTraces(ctx, int(req.Limit))
	res := make([]*gateonv1.Trace, 0, len(traces))
	for _, t := range traces {
		reqHeaders := make(map[string]string)
		if t.RequestHeaders != "" {
			_ = json.Unmarshal([]byte(t.RequestHeaders), &reqHeaders)
		}
		respHeaders := make(map[string]string)
		if t.ResponseHeaders != "" {
			_ = json.Unmarshal([]byte(t.ResponseHeaders), &respHeaders)
		}

		res = append(res, &gateonv1.Trace{
			Id:              t.ID,
			OperationName:   t.OperationName,
			ServiceName:     t.ServiceName,
			DurationMs:      t.DurationMs,
			Timestamp:       t.Timestamp.Format(time.RFC3339),
			Status:          t.Status,
			Path:            t.Path,
			SourceIp:        t.SourceIP,
			UserAgent:       t.UserAgent,
			Method:          t.Method,
			Referer:         t.Referer,
			RequestUri:      t.RequestURI,
			RequestHeaders:  reqHeaders,
			RequestBody:     t.RequestBody,
			ResponseHeaders: respHeaders,
			ResponseBody:    t.ResponseBody,
		})
	}
	return &gateonv1.ListTracesResponse{Traces: res}, nil
}

func (s *ApiService) TraceRoute(ctx context.Context, req *gateonv1.TraceRouteRequest) (*gateonv1.TraceRouteResponse, error) {
	if req.Ip == "" {
		return nil, status.Error(codes.InvalidArgument, "IP address is required")
	}

	serverIP := getPublicIP()
	hops, err := telemetry.TraceRoute(ctx, req.Ip, serverIP)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to perform traceroute: %v", err)
	}

	return &gateonv1.TraceRouteResponse{
		Hops: hops,
	}, nil
}
