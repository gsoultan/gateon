// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// openTraceStore points the process-global trace store at a directory of the
// test's own; the close first is what makes the open real (see freshStore in
// internal/telemetry).
func openTraceStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(dir, "pebble"))
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "telemetry.db"), 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
}

// A trace that has left the live store is still found by the period query and
// still opens in full: the dashboard's detail view asks GetTrace for whatever
// QueryTraces listed, without knowing which of the two held it.
func TestTraceArchive_AnArchivedTraceIsFoundAndOpens(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	t.Setenv(tracearchive.EnvDir, t.TempDir())
	t.Setenv(tracearchive.EnvEnabled, "true")
	t.Setenv(tracearchive.EnvNodeName, "gw-api")
	openTraceStore(t)

	at := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	telemetry.RecordTrace("archived-1", "GET /orders", "svc", "route-1", 12.5, at, "502", "/orders",
		"198.51.100.7", "", "NL", "curl/8", "GET", "", "/orders?id=9", "", "",
		map[string][]string{"Accept": {"*/*"}}, nil, "none", 40, 0, 0, 0, 0)
	telemetry.FlushTraces()
	(&tracearchive.Archiver{}).ArchiveNow(context.Background())

	// A new, empty store: the trace now exists only in the archive.
	openTraceStore(t)
	s := &ApiService{}

	q, err := s.QueryTraces(context.Background(), &gateonv1.QueryTracesRequest{
		From:   at.Add(-time.Hour).Format(time.RFC3339),
		To:     at.Add(time.Hour).Format(time.RFC3339),
		Status: "5xx",
	})
	if err != nil {
		t.Fatalf("QueryTraces: %v", err)
	}
	if len(q.Traces) != 1 || q.Traces[0].Id != "archived-1" || q.NextCursor != "" {
		t.Fatalf("QueryTraces = %+v, want the one archived trace and no further page", q)
	}
	if q.Traces[0].Node != "gw-api" {
		t.Fatalf("the trace's node = %q, want the gateway that recorded it", q.Traces[0].Node)
	}
	list, err := s.ListTraceArchives(context.Background(), &gateonv1.ListTraceArchivesRequest{})
	if err != nil {
		t.Fatalf("ListTraceArchives: %v", err)
	}
	seg := tracearchive.SegmentAt(at)
	if segs := list.GetSegments(); len(segs) != 1 || segs[0].Node != "gw-api" || segs[0].Name != seg.FileName("gw-api") ||
		list.GetStatus().GetNode() != "gw-api" {
		t.Fatalf("ListTraceArchives = %+v, want gw-api's one hour, named for it", list)
	}

	got, err := s.GetTrace(context.Background(), &gateonv1.GetTraceRequest{Id: "archived-1", Timestamp: q.Traces[0].Timestamp})
	if err != nil {
		t.Fatalf("GetTrace: %v", err)
	}
	if tr := got.GetTrace(); tr.RequestUri != "/orders?id=9" || tr.RequestHeaders["Accept"] != "*/*" || tr.Status != "502" {
		t.Fatalf("GetTrace = %+v, want the archived trace in full", tr)
	}
	if _, err := s.GetTrace(context.Background(), &gateonv1.GetTraceRequest{Id: "never", Timestamp: q.Traces[0].Timestamp}); status.Code(err) != codes.NotFound {
		t.Fatalf("an unknown trace: %v, want NotFound", err)
	}
}

// A refused query says why, as InvalidArgument, so the dashboard can show the
// reason instead of a generic failure.
func TestQueryTraces_RefusesABadPeriodAsInvalidArgument(t *testing.T) {
	s := &ApiService{}
	now := time.Now().UTC()
	for name, req := range map[string]*gateonv1.QueryTracesRequest{
		"no from":     {To: now.Format(time.RFC3339)},
		"not a time":  {From: "yesterday", To: now.Format(time.RFC3339)},
		"backwards":   {From: now.Format(time.RFC3339), To: now.Add(-time.Hour).Format(time.RFC3339)},
		"bad status":  {From: now.Add(-time.Hour).Format(time.RFC3339), To: now.Format(time.RFC3339), Status: "teapot"},
		"bad cursor":  {From: now.Add(-time.Hour).Format(time.RFC3339), To: now.Format(time.RFC3339), Cursor: "%%%"},
		"over a year": {From: now.AddDate(-2, 0, 0).Format(time.RFC3339), To: now.Format(time.RFC3339)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.QueryTraces(context.Background(), req)
			if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || st.Message() == "" {
				t.Fatalf("QueryTraces = %v, want InvalidArgument with a reason", err)
			}
		})
	}
}

func TestListTraceArchives_ReportsTheArchive(t *testing.T) {
	t.Setenv(tracearchive.EnvDir, t.TempDir())
	t.Setenv(tracearchive.EnvEnabled, "true")
	t.Setenv(tracearchive.EnvRetentionDays, "30")
	res, err := (&ApiService{}).ListTraceArchives(context.Background(), &gateonv1.ListTraceArchivesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st := res.GetStatus(); !st.GetEnabled() || st.GetRetentionDays() != 30 || len(res.GetSegments()) != 0 {
		t.Fatalf("ListTraceArchives = %+v, want an enabled, empty archive kept 30 days", res)
	}
	if _, err := (&ApiService{}).ListTraceArchives(context.Background(), &gateonv1.ListTraceArchivesRequest{PageToken: "../x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a forged page token: %v, want InvalidArgument", err)
	}
	// The counts are the running archiver's; what is reported of them is this.
	st := traceArchiveStatus(tracearchive.Status{Settings: tracearchive.Settings{Node: "gw-a"}, Nodes: []string{"gw-a", "gw-b"}})
	if st.GetNode() != "gw-a" || !slices.Equal(st.GetNodes(), []string{"gw-a", "gw-b"}) {
		t.Fatalf("status = %+v, want this node and both", st)
	}
}

// Over Connect, as the dashboard calls them. ApiService answers in grpc-go
// statuses, which connect-go sends as Unknown over HTTP 500 unless they are
// converted: a trace that has gone read as a failure to retry, and the message
// was "rpc error: code = NotFound desc = ...".
func TestTraceRPCs_KeepTheirCodesOverConnect(t *testing.T) {
	t.Setenv(tracearchive.EnvDir, t.TempDir())
	_, handler := gateonv1connect.NewApiServiceHandler(NewConnectHandler(&ApiService{}),
		connect.WithInterceptors(StatusInterceptor()))
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client := gateonv1connect.NewApiServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := client.GetTrace(ctx, connect.NewRequest(&gateonv1.GetTraceRequest{Id: "gone", Timestamp: now.Format(time.RFC3339Nano)}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetTrace of a missing trace: %v, want NotFound", err)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Message() != "trace not found" {
		t.Fatalf("message = %q, want the status's own", ce.Message())
	}

	_, err = client.QueryTraces(ctx, connect.NewRequest(&gateonv1.QueryTracesRequest{
		From: now.Format(time.RFC3339), To: now.Add(-time.Hour).Format(time.RFC3339),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !errors.As(err, &ce) || strings.Contains(ce.Message(), "rpc error") {
		t.Fatalf("QueryTraces with a backwards period: %v, want InvalidArgument with a plain reason", err)
	}
}

// connectCode converts gRPC statuses and nothing else: a Connect error already
// says what it means, and an error with no status has no code to carry.
func TestConnectCode_PassesThroughWhatItDoesNotConvert(t *testing.T) {
	if connectCode(nil) != nil {
		t.Fatal("no error became one")
	}
	plain := errors.New("request is required")
	if got := connectCode(plain); got != plain { //nolint:errorlint // identity is the property under test
		t.Fatalf("a plain error became %v", got)
	}
	already := connect.NewError(connect.CodePermissionDenied, errors.New("no"))
	if got := connectCode(already); got != error(already) { //nolint:errorlint // identity is the property under test
		t.Fatalf("a Connect error became %v", got)
	}
	converted := connectCode(status.Error(codes.ResourceExhausted, "busy"))
	var ce *connect.Error
	if !errors.As(converted, &ce) || ce.Code() != connect.CodeResourceExhausted || ce.Message() != "busy" {
		t.Fatalf("a status became %v", converted)
	}

	// What a probed backend answered, wrapped by the RPC that probed it, is the
	// backend's code, not the caller's. Carried across, a backend's
	// Unauthenticated would sign the dashboard's administrator out.
	// PermissionDenied is the case that shows it: a code that would convert,
	// and would tell the administrator their own role lacks access.
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated} {
		foreign := fmt.Errorf("failed to create reflection stream: %w", status.Error(code, "backend says no"))
		if got := connectCode(foreign); got != foreign { //nolint:errorlint // identity is the property under test
			t.Fatalf("a backend's wrapped %v became %v", code, got)
		}
	}
	own := status.Error(codes.Unauthenticated, "no")
	if got := connectCode(own); got != own { //nolint:errorlint // identity is the property under test
		t.Fatalf("Unauthenticated was converted to %v; only a real session expiry may say that", got)
	}
}

// A search the archive refuses for what it would hold is ResourceExhausted, in
// words fit to show; the node it stopped at stays in the log.
func TestTraceArchiveError_ASearchTooLargeIsResourceExhausted(t *testing.T) {
	err := traceArchiveError("query", fmt.Errorf("%w: node gw-7", tracearchive.ErrTooLarge))
	if st, _ := status.FromError(err); st.Code() != codes.ResourceExhausted || strings.Contains(st.Message(), "gw-7") {
		t.Fatalf("traceArchiveError = %v, want ResourceExhausted without the detail", err)
	}
}
