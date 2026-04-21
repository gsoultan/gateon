package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetDiagnostics_Enhanced(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Mock stores
	epStore := config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	svcStore := config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))

	// Setup data
	ep := &gateonv1.EntryPoint{
		Id:      "ep1",
		Name:    "HTTP",
		Address: ":80",
		Type:    gateonv1.EntryPoint_HTTP,
	}
	_ = epStore.Update(ctx, ep)

	svc := &gateonv1.Service{
		Id:   "svc1",
		Name: "MyService",
	}
	_ = svcStore.Update(ctx, svc)

	mw := &gateonv1.Middleware{
		Id:   "mw1",
		Name: "Auth",
		Type: "auth",
	}
	_ = mwStore.Update(ctx, mw)

	rt := &gateonv1.Route{
		Id:          "rt1",
		Name:        "Route1",
		Entrypoints: []string{"ep1"},
		ServiceId:   "svc1",
		Middlewares: []string{"mw1"},
		Rule:        "Path(`/api`)",
	}
	_ = routeStore.Update(ctx, rt)

	apiSvc := NewApiService(ApiServiceConfig{
		EntryPoints: epStore,
		Routes:      routeStore,
		Services:    svcStore,
		Middlewares: mwStore,
		RouteStatsProvider: func(routeID string) []proxy.TargetStats {
			if routeID == "rt1" {
				return []proxy.TargetStats{
					{URL: "http://localhost:8080", Alive: true},
				}
			}
			return nil
		},
	})

	resp, err := apiSvc.GetDiagnostics(ctx, &gateonv1.GetDiagnosticsRequest{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Len(t, resp.Entrypoints, 1)
	diagEP := resp.Entrypoints[0]
	assert.Equal(t, "ep1", diagEP.Id)
	assert.Len(t, diagEP.Routes, 1)

	diagRoute := diagEP.Routes[0]
	assert.Equal(t, "rt1", diagRoute.Id)
	assert.Equal(t, "MyService", diagRoute.ServiceName)
	assert.True(t, diagRoute.ServiceHealthy)
	assert.True(t, diagRoute.Healthy)

	assert.Len(t, diagRoute.Middlewares, 1)
	diagMW := diagRoute.Middlewares[0]
	assert.Equal(t, "mw1", diagMW.Id)
	assert.Equal(t, "Auth", diagMW.Name)
	assert.True(t, diagMW.Healthy)
}

func TestGetDiagnostics_ServiceDown(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	epStore := config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	svcStore := config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))

	_ = epStore.Update(ctx, &gateonv1.EntryPoint{Id: "ep1", Name: "HTTP", Type: gateonv1.EntryPoint_HTTP})
	_ = svcStore.Update(ctx, &gateonv1.Service{Id: "svc1", Name: "MyService"})
	_ = routeStore.Update(ctx, &gateonv1.Route{
		Id: "rt1", Name: "Route1", Entrypoints: []string{"ep1"}, ServiceId: "svc1",
	})

	apiSvc := NewApiService(ApiServiceConfig{
		EntryPoints: epStore,
		Routes:      routeStore,
		Services:    svcStore,
		Middlewares: mwStore,
		RouteStatsProvider: func(routeID string) []proxy.TargetStats {
			return []proxy.TargetStats{
				{URL: "http://localhost:8080", Alive: false},
			}
		},
	})

	resp, _ := apiSvc.GetDiagnostics(ctx, &gateonv1.GetDiagnosticsRequest{})
	diagRoute := resp.Entrypoints[0].Routes[0]
	assert.False(t, diagRoute.ServiceHealthy)
	assert.False(t, diagRoute.Healthy)
	assert.Equal(t, "All backend targets are down", diagRoute.Error)
}

func TestAnomalyAnalysisEngine_RealWorld(t *testing.T) {
	engine := NewAnomalyAnalysisEngine()
	ctx := context.Background()

	now := time.Now()

	traces := []telemetry.TraceRecord{
		// Brute force from IP 1.2.3.4 (11 failures)
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "401 Unauthorized", Timestamp: now, Path: "/login", DurationMs: 100},
		{SourceIP: "1.2.3.4", Status: "403 Forbidden", Timestamp: now, Path: "/admin", DurationMs: 100},

		// Scanner from IP 5.6.7.8 (21 404s)
		{SourceIP: "5.6.7.8", Status: "404 Not Found", Timestamp: now, Path: "/.env", DurationMs: 50},
		{SourceIP: "5.6.7.8", Status: "404 Not Found", Timestamp: now, Path: "/wp-admin", DurationMs: 50},
	}

	// Add 19 more 404s for 5.6.7.8
	for i := 0; i < 19; i++ {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "5.6.7.8", Status: "404 Not Found", Timestamp: now, Path: "/scan", DurationMs: 50,
		})
	}

	// Slow client from IP 9.9.9.9 (6 requests, 6000ms avg)
	for i := 0; i < 6; i++ {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "9.9.9.9", Status: "200 OK", Timestamp: now, Path: "/", DurationMs: 6000,
		})
	}

	// High traffic from 10.10.10.10 (101 requests)
	for i := 0; i < 101; i++ {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "10.10.10.10", Status: "200 OK", Timestamp: now, Path: "/", DurationMs: 10,
		})
	}

	data := &DiagnosticData{
		Traces: traces,
	}

	anomalies := engine.Analyze(ctx, data)

	foundBruteForce := false
	foundScanner := false
	foundSlowClient := false
	foundHighTraffic := false

	for _, a := range anomalies {
		switch a.Type {
		case "brute_force_attempt":
			if a.Source == "1.2.3.4" {
				foundBruteForce = true
				assert.NotEmpty(t, a.Recommendation)
			}
		case "security_scan":
			if a.Source == "5.6.7.8" {
				foundScanner = true
				assert.NotEmpty(t, a.Recommendation)
			}
		case "slow_client_anomaly":
			if a.Source == "9.9.9.9" {
				foundSlowClient = true
				assert.NotEmpty(t, a.Recommendation)
			}
		case "high_traffic":
			if a.Source == "10.10.10.10" {
				foundHighTraffic = true
				assert.NotEmpty(t, a.Recommendation)
			}
		}
	}

	assert.True(t, foundBruteForce, "Should detect brute force")
	assert.True(t, foundScanner, "Should detect scanner")
	assert.True(t, foundSlowClient, "Should detect slow client")
	assert.True(t, foundHighTraffic, "Should detect high traffic")
}

func TestApplyRecommendation(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	epStore := config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	svcStore := config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))
	globalStore := config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))

	_ = routeStore.Update(ctx, &gateonv1.Route{Id: "rt1", Name: "Route1"})

	apiSvc := NewApiService(ApiServiceConfig{
		EntryPoints: epStore,
		Routes:      routeStore,
		Services:    svcStore,
		Middlewares: mwStore,
		Globals:     globalStore,
	})

	t.Run("Block IP", func(t *testing.T) {
		resp, err := apiSvc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "security_scan",
			Source:      "1.2.3.4",
		})
		assert.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "1.2.3.4 blocked")

		// Verify middleware created
		mw, ok := mwStore.Get(ctx, "block-ip-1-2-3-4")
		assert.True(t, ok)
		assert.Equal(t, "ipfilter", mw.Type)
		assert.Equal(t, "1.2.3.4", mw.Config["deny_list"])

		// Verify route updated
		rt, _ := routeStore.Get(ctx, "rt1")
		assert.Contains(t, rt.Middlewares, "block-ip-1-2-3-4")
	})

	t.Run("Disable Management", func(t *testing.T) {
		_ = globalStore.Update(ctx, &gateonv1.GlobalConfig{
			Management: &gateonv1.ManagementConfig{AllowPublicManagement: true},
		})

		resp, err := apiSvc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "management_access_violation",
		})
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify global config updated
		conf := globalStore.Get(ctx)
		assert.False(t, conf.Management.AllowPublicManagement)
	})

	t.Run("Fix Shadowed Route", func(t *testing.T) {
		_ = routeStore.Update(ctx, &gateonv1.Route{Id: "rt-spec", Name: "Specific", Priority: 50})

		resp, err := apiSvc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "shadowed_route",
			Source:      "rt-spec",
		})
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		rt, _ := routeStore.Get(ctx, "rt-spec")
		assert.Equal(t, int32(150), rt.Priority)
	})
}

func TestShadowedRouteDetection(t *testing.T) {
	engine := NewAnomalyAnalysisEngine()
	ctx := context.Background()

	data := &DiagnosticData{
		Routes: []*gateonv1.Route{
			{
				Id:          "rt-generic",
				Name:        "Generic Route",
				Entrypoints: []string{"ep1"},
				Rule:        "Host(`example.com`)",
				Priority:    100,
			},
			{
				Id:          "rt-specific",
				Name:        "Specific Route",
				Entrypoints: []string{"ep1"},
				Rule:        "Host(`example.com`) && PathPrefix(`/api`)",
				Priority:    50,
			},
		},
	}

	anomalies := engine.Analyze(ctx, data)
	found := false
	for _, a := range anomalies {
		if a.Type == "shadowed_route" && a.Source == "rt-specific" {
			found = true
			assert.Contains(t, a.Description, "shadowed by 'Generic Route'")
		}
	}
	assert.True(t, found, "Should detect shadowed route")
}
