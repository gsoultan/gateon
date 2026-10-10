// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// TestColdCacheDiagnosticsRunOnePass: until the analysis loop's first pass
// lands in anomaliesCache -- a minute after start, longer when a pass is slow --
// GetDiagnostics ran a whole detection pass inline, once per request. Several
// dashboards open at startup were several passes at once on a 2-core host, and
// with anomaly detection on, each trains go-iforest, whose Train writes a
// package-global (iforest.MaxDepth): concurrent passes are a data race.
// Meaningful under -race, which is how CI runs it.
func TestColdCacheDiagnosticsRunOnePass(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	gc := proto.Clone(globals.Get(ctx)).(*gateonv1.GlobalConfig)
	gc.AnomalyDetection = &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 0.5, CheckIntervalSeconds: 60}
	if err := globals.Update(ctx, gc); err != nil {
		t.Fatal(err)
	}
	// GetDiagnostics lists middlewares once per request and detectAnomalies once
	// per pass, so the count says how many passes ran.
	mws := &countingMiddlewares{MiddlewareStore: config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))}
	s := NewApiService(ApiServiceConfig{
		EntryPoints: config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json")),
		Routes:      config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		Services:    config.NewServiceRegistry(filepath.Join(dir, "services.json")),
		Middlewares: mws,
		Globals:     globals,
	})

	_ = telemetry.ClosePathStatsStore(ctx)
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "traces.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(ctx) })
	// Enough distinct clients for the isolation forest to train (it needs 20).
	start := time.Now().Add(-5 * time.Minute)
	for c := range 30 {
		for r := range 6 {
			telemetry.RecordTrace(fmt.Sprintf("cold-%d-%d", c, r), "GET /", "rt1", "svc1", 10,
				start.Add(time.Duration(c*6+r)*time.Second), "200", "/", fmt.Sprintf("10.50.0.%d", c+1),
				"", "", "Mozilla/5.0", "GET", "", "/", "", "", nil, nil, "", 100, 0, 0, 0, 0)
		}
	}
	telemetry.FlushTraces()

	const requests = 4
	getDiagnosticsConcurrently(t, s, requests)
	if passes := mws.lists.Load() - requests; passes != 1 {
		t.Errorf("%d dashboards asked for diagnostics before the first published pass and %d passes ran", requests, passes)
	}
	getDiagnosticsConcurrently(t, s, 1)
	if passes := mws.lists.Load() - requests - 1; passes != 1 {
		t.Errorf("a later request ran another pass (%d in all); the first one was not published", passes)
	}
}

// TestOverlappingDetectionPassesDoNotRace: the analysis loop's pass and a
// Diagnostics request's cold-cache pass are separate callers of
// detectAnomalies and can overlap; each trains a forest, and go-iforest's Train
// writes a package global. Meaningful under -race.
func TestOverlappingDetectionPassesDoNotRace(t *testing.T) {
	data := func() *DiagnosticData {
		d := &DiagnosticData{}
		at := time.Now().Add(-5 * time.Minute)
		for c := range 25 {
			for r := range 6 {
				d.Traces = append(d.Traces, &telemetry.TraceRecord{ServiceDelay: 1,
					SourceIP: fmt.Sprintf("10.52.0.%d", c+1), Path: "/", Method: "GET", Status: "200",
					DurationMs: 10, Timestamp: at.Add(time.Duration(c*6+r) * time.Second),
				})
			}
		}
		return d
	}
	cfg := &gateonv1.GlobalConfig{AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true}}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		wg.Go(func() {
			<-start
			NewAnomalyAnalysisEngine(cfg, nil).Analyze(t.Context(), data())
		})
	}
	close(start)
	wg.Wait()
}

type countingMiddlewares struct {
	config.MiddlewareStore
	lists atomic.Int32
}

func (c *countingMiddlewares) List(ctx context.Context) []*gateonv1.Middleware {
	c.lists.Add(1)
	return c.MiddlewareStore.List(ctx)
}

// TestWarmCacheDiagnosticsDoNotShareASlice: every dashboard's watch stream
// calls GetDiagnostics every five seconds, and each call took the cached slice
// itself, appended recent threats to it and sorted it in place. Two dashboards
// open at once were two goroutines permuting and writing past the end of the
// one slice the analysis loop published. Meaningful under -race.
func TestWarmCacheDiagnosticsDoNotShareASlice(t *testing.T) {
	dir := t.TempDir()
	s := NewApiService(ApiServiceConfig{
		EntryPoints: config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json")),
		Routes:      config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		Services:    config.NewServiceRegistry(filepath.Join(dir, "services.json")),
		Middlewares: config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
	})
	// A published pass the way Analyze builds one: appended, so it has spare
	// capacity past its length.
	var published []*gateonv1.Anomaly
	for i := range 9 {
		published = append(published, &gateonv1.Anomaly{
			Type: "unlisted_route", Source: fmt.Sprintf("10.51.0.%d", i), Score: float64(i),
		})
	}
	s.anomaliesCache.Store(&published)

	getDiagnosticsConcurrently(t, s, 4)
}

// getDiagnosticsConcurrently releases n GetDiagnostics calls at once.
func getDiagnosticsConcurrently(t *testing.T, s *ApiService, n int) {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			if _, err := s.GetDiagnostics(t.Context(), &gateonv1.GetDiagnosticsRequest{}); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
}
