// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ApiService) GetStatus(ctx context.Context, _ *gateonv1.GetStatusRequest) (*gateonv1.GetStatusResponse, error) {
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
	activeTier := config.ResolveProfile()
	profilePinned := os.Getenv("GATEON_PROFILE") != ""

	return &gateonv1.GetStatusResponse{
		Status:              "running",
		Version:             s.Version,
		Uptime:              int64(stats.UptimeSeconds),
		MemoryUsage:         int64(stats.MemoryAllocBytes),
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
		Profile:             string(activeTier),
		ProfilePinned:       profilePinned,
	}, nil
}

func (s *ApiService) ListTraces(ctx context.Context, req *gateonv1.ListTracesRequest) (*gateonv1.ListTracesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	traces := telemetry.GetTracesFiltered(ctx, int(req.Limit), req.Summary)
	res := make([]*gateonv1.Trace, 0, len(traces))
	for _, t := range traces {
		res = append(res, traceToProto(t, !req.Summary))
	}
	return &gateonv1.ListTracesResponse{Traces: res}, nil
}

// GetTrace returns one trace in full. The live store is asked first; a trace
// that has aged out of it is looked up in the trace archive, so a trace found
// by QueryTraces opens whichever of the two holds it.
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
		if t, err = tracearchive.Lookup(ctx, ts, req.Id); err != nil {
			logger.L.LogError("trace archive: lookup failed", "error", err, "trace_id", req.Id)
			return nil, status.Error(codes.Internal, "could not read the trace archive")
		}
	}
	if t == nil {
		return nil, status.Error(codes.NotFound, "trace not found")
	}
	return &gateonv1.GetTraceResponse{Trace: traceToProto(t, true)}, nil
}

// QueryTraces returns a page of the traces whose requests started in a
// period. The part of the period the live store still holds is read from it,
// the part before that from the trace archive; the caller sees one timeline.
func (s *ApiService) QueryTraces(ctx context.Context, req *gateonv1.QueryTracesRequest) (*gateonv1.QueryTracesResponse, error) {
	q, err := traceQuery(req)
	if err != nil {
		return nil, err
	}
	res, err := tracearchive.Search(ctx, q)
	if err != nil {
		return nil, traceArchiveError("query", err)
	}
	out := &gateonv1.QueryTracesResponse{
		Traces:     make([]*gateonv1.Trace, 0, len(res.Traces)),
		NextCursor: res.NextCursor,
		Partial:    res.Partial,
		ScannedTo:  formatTime(res.ScannedTo),
	}
	for _, t := range res.Traces {
		out.Traces = append(out.Traces, traceToProto(t, false))
	}
	return out, nil
}

func traceQuery(req *gateonv1.QueryTracesRequest) (tracearchive.Query, error) {
	from, err := time.Parse(time.RFC3339Nano, req.GetFrom())
	if err != nil {
		return tracearchive.Query{}, status.Error(codes.InvalidArgument, "from must be an RFC 3339 time")
	}
	to, err := time.Parse(time.RFC3339Nano, req.GetTo())
	if err != nil {
		return tracearchive.Query{}, status.Error(codes.InvalidArgument, "to must be an RFC 3339 time")
	}
	return tracearchive.Query{
		From:        from,
		To:          to,
		Limit:       int(req.GetLimit()),
		Cursor:      req.GetCursor(),
		OldestFirst: req.GetOldestFirst(),
		Filter:      tracearchive.Filter{Status: req.GetStatus(), Method: req.GetMethod(), Text: req.GetText()},
	}, nil
}

// ListTraceArchives lists the archived hours, newest first, with the
// archive's state.
func (s *ApiService) ListTraceArchives(_ context.Context, req *gateonv1.ListTraceArchivesRequest) (*gateonv1.ListTraceArchivesResponse, error) {
	from, err := optionalTime("from", req.GetFrom())
	if err != nil {
		return nil, err
	}
	to, err := optionalTime("to", req.GetTo())
	if err != nil {
		return nil, err
	}
	segs, next, err := tracearchive.List(from, to, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, traceArchiveError("list", err)
	}
	out := &gateonv1.ListTraceArchivesResponse{
		Segments:      make([]*gateonv1.TraceArchiveSegment, 0, len(segs)),
		NextPageToken: next,
		Status:        traceArchiveStatus(tracearchive.Default().Status()),
	}
	for _, sg := range segs {
		out.Segments = append(out.Segments, &gateonv1.TraceArchiveSegment{
			Name:        sg.Segment.Name(),
			PeriodStart: formatTime(sg.Segment.Start()),
			PeriodEnd:   formatTime(sg.Segment.End()),
			SizeBytes:   sg.Size,
			TraceCount:  sg.Traces,
			ArchivedAt:  formatTime(sg.Archived),
		})
	}
	return out, nil
}

// OpenTraceArchive opens an archived hour for download. It is not an RPC: an
// hour of traces is streamed from disk, and a unary response would hold all of
// it in memory first.
func (s *ApiService) OpenTraceArchive(name string) (*tracearchive.Download, error) {
	return tracearchive.OpenDownload(name)
}

func traceArchiveStatus(st tracearchive.Status) *gateonv1.TraceArchiveStatus {
	return &gateonv1.TraceArchiveStatus{
		Enabled:          st.Settings.Enabled,
		TraceStoreActive: st.TraceStoreActive,
		RetentionDays:    int32(min(st.Settings.RetentionDays, math.MaxInt32)),
		MaxSizeBytes:     st.Settings.MaxBytes,
		SegmentCount:     int64(st.Segments),
		TotalSizeBytes:   st.TotalBytes,
		OldestPeriod:     formatTime(st.Oldest),
		NewestPeriod:     formatTime(st.Newest),
		LastArchivedAt:   formatTime(st.LastWritten),
		LastError:        st.LastError,
		LastErrorAt:      formatTime(st.LastErrorAt),
	}
}

// traceArchiveError turns a trace archive failure into a status. A refused
// query says why, in the archive's own fixed words; anything else is logged
// and answered in general terms, because its text names paths on the
// gateway's disk.
func traceArchiveError(op string, err error) error {
	switch {
	case errors.Is(err, tracearchive.ErrInvalidQuery):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, tracearchive.ErrBusy):
		return status.Error(codes.ResourceExhausted, "another trace search is running; try again in a moment")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	logger.L.LogError("trace archive: request failed", "op", op, "error", err)
	return status.Error(codes.Internal, "could not read the trace archive")
}

func optionalTime(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, status.Errorf(codes.InvalidArgument, "%s must be an RFC 3339 time", field)
	}
	return t, nil
}

// formatTime renders a time for the API, or nothing for the zero time.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// traceToProto converts a stored trace. Headers are parsed only for a full
// trace; a summary does not carry them.
func traceToProto(t *telemetry.TraceRecord, full bool) *gateonv1.Trace {
	var reqHeaders, respHeaders map[string]string
	if full {
		reqHeaders = telemetry.ParseHeaders(t.RequestHeaders)
		respHeaders = telemetry.ParseHeaders(t.ResponseHeaders)
	}
	return &gateonv1.Trace{
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
	}
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
