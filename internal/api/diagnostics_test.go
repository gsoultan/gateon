package api

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetDiagnostics_Enhanced(t *testing.T) {
	ctx := t.Context()
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
	ctx := t.Context()
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
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{
			SecurityThreatThreshold: 30.0,
		},
	}, nil)
	ctx := t.Context()

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
	for range 19 {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "5.6.7.8", Status: "404 Not Found", Timestamp: now, Path: "/scan", DurationMs: 50,
		})
	}

	// Slow client from IP 9.9.9.9 (6 requests, 6000ms avg)
	for range 6 {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "9.9.9.9", Status: "200 OK", Timestamp: now, Path: "/", DurationMs: 6000,
		})
	}

	// High traffic from 10.10.10.10 (201 requests)
	for range 201 {
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
		case "security_scan", "honeypot_hit":
			if a.Source == "5.6.7.8" {
				foundScanner = true
				assert.NotEmpty(t, a.Recommendation)
			}
		case "slow_client_anomaly":
			if a.Source == "9.9.9.9" {
				foundSlowClient = true
				assert.NotEmpty(t, a.Recommendation)
			}
		case "high_traffic", "security_threat":
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

func TestSecurityThreatDetector_Advanced(t *testing.T) {
	ctx := t.Context()
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{
			SecurityThreatThreshold: 30.0,
		},
	}, nil)
	now := time.Now()

	traces := []telemetry.TraceRecord{}

	// 1. Burst from IP 1.1.1.1 (40 requests in same 10s slot)
	for range 40 {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "1.1.1.1", Status: "200 OK", Timestamp: now, Path: "/", Method: "GET",
		})
	}

	// 2. Suspicious Referer from IP 2.2.2.2
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "2.2.2.2", Status: "200 OK", Timestamp: now, Path: "/", Method: "GET", Referer: "http://evil.com/exploit",
	})

	// 3. Coordinated Scan from 3.3.3.3 and 4.4.4.4 on same suspicious path
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "3.3.3.3", Status: "404 Not Found", Timestamp: now, Path: "/.env", Method: "GET",
	})
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "4.4.4.4", Status: "404 Not Found", Timestamp: now, Path: "/.env", Method: "GET",
	})

	// 4. Unusual POST-only traffic from 5.5.5.5
	for range 25 {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "5.5.5.5", Status: "200 OK", Timestamp: now, Path: "/api/submit", Method: "POST",
		})
	}

	data := &DiagnosticData{
		Traces: traces,
	}

	anomalies := engine.Analyze(ctx, data)

	foundBurst := false
	foundReferer := false
	foundCoordinated := 0
	foundPostOnly := false

	for _, a := range anomalies {
		if a.Source == "1.1.1.1" && strings.Contains(strings.ToLower(a.Description), "burst") {
			foundBurst = true
		}
		if a.Source == "2.2.2.2" && strings.Contains(strings.ToLower(a.Description), "referer") {
			foundReferer = true
		}
		if (a.Source == "3.3.3.3" || a.Source == "4.4.4.4") && strings.Contains(strings.ToLower(a.Description), "coordinated") {
			foundCoordinated++
		}
		if a.Source == "5.5.5.5" && strings.Contains(strings.ToLower(a.Description), "post-only") {
			foundPostOnly = true
		}
	}

	assert.True(t, foundBurst, "Should detect burst from 1.1.1.1")
	assert.True(t, foundReferer, "Should detect suspicious referer from 2.2.2.2")
	assert.GreaterOrEqual(t, foundCoordinated, 2, "Should detect coordinated scan from 3.3.3.3 and 4.4.4.4")
	assert.True(t, foundPostOnly, "Should detect POST-only traffic from 5.5.5.5")
}

func TestSecurityThreatDetector_ComplexScenarios(t *testing.T) {
	ctx := t.Context()
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{
			SecurityThreatThreshold: 30.0,
		},
	}, nil)
	now := time.Now()

	traces := []telemetry.TraceRecord{}

	// 1. Targeted Brute Force on /login (IP 6.6.6.6)
	for range 6 {
		traces = append(traces, telemetry.TraceRecord{
			SourceIP: "6.6.6.6", Status: "401 Unauthorized", Timestamp: now, Path: "/login", Method: "POST",
		})
	}

	// 2. SSRF Attempt (IP 7.7.7.7)
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "7.7.7.7", Status: "200 OK", Timestamp: now, Path: "/api/fetch?url=http://169.254.169.254/latest/meta-data", Method: "GET",
	})

	// 3. Command Injection Attempt (IP 8.8.8.8)
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "8.8.8.8", Status: "200 OK", Timestamp: now, Path: "/search?q=;whoami", Method: "GET",
	})

	// 4. JA3 Fingerprint Rotation (IP 9.9.9.9)
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "9.9.9.9", Status: "200 OK", Timestamp: now, Path: "/", Method: "GET", JA3: "fingerprint1",
	})
	traces = append(traces, telemetry.TraceRecord{
		SourceIP: "9.9.9.9", Status: "200 OK", Timestamp: now, Path: "/api", Method: "GET", JA3: "fingerprint2",
	})

	data := &DiagnosticData{
		Traces: traces,
	}

	anomalies := engine.Analyze(ctx, data)

	foundTargetedBruteForce := false
	foundSSRF := false
	foundCmdInjection := false
	foundJA3Rotation := false

	for _, a := range anomalies {
		if a.Source == "6.6.6.6" && strings.Contains(strings.ToLower(a.Description), "targeted brute force") {
			foundTargetedBruteForce = true
		}
		if a.Source == "7.7.7.7" && strings.Contains(strings.ToLower(a.Description), "suspicious paths/payloads") {
			// SSRF is handled by analyzePatterns which adds "suspicious paths/payloads"
			foundSSRF = true
		}
		if a.Source == "8.8.8.8" && strings.Contains(strings.ToLower(a.Description), "suspicious paths/payloads") {
			foundCmdInjection = true
		}
		if a.Source == "9.9.9.9" && strings.Contains(strings.ToLower(a.Description), "multiple tls fingerprints") {
			foundJA3Rotation = true
		}
	}

	assert.True(t, foundTargetedBruteForce, "Should detect targeted brute force from 6.6.6.6")
	assert.True(t, foundSSRF, "Should detect SSRF from 7.7.7.7")
	assert.True(t, foundCmdInjection, "Should detect command injection from 8.8.8.8")
	assert.True(t, foundJA3Rotation, "Should detect JA3 rotation from 9.9.9.9")
}

func TestApplyRecommendation(t *testing.T) {
	ctx := t.Context()
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
		assert.Contains(t, resp.Message, "1.2.3.4 blocked via middleware")

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

func TestRemoveMitigatedThreat(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()

	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))

	s := NewApiService(ApiServiceConfig{
		Middlewares: mwStore,
		Routes:      routeStore,
	})

	ip := "1.2.3.4"
	mwID := "block-ip-1-2-3-4"

	// Setup initial state: IP is blocked
	_ = mwStore.Update(ctx, &gateonv1.Middleware{
		Id:   mwID,
		Name: "Auto-Block: " + ip,
		Type: "ipfilter",
	})
	_ = routeStore.Update(ctx, &gateonv1.Route{
		Id:          "route1",
		Middlewares: []string{mwID, "other-mw"},
	})

	// Perform removal
	res, err := s.RemoveMitigatedThreat(ctx, &gateonv1.RemoveMitigatedThreatRequest{
		Source: ip,
	})
	if err != nil {
		t.Fatalf("RemoveMitigatedThreat failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("RemoveMitigatedThreat response indicates failure: %s", res.Message)
	}

	// Verify middleware is deleted
	_, ok := mwStore.Get(ctx, mwID)
	if ok {
		t.Error("Middleware should have been deleted")
	}

	// Verify route is updated
	rt, ok := routeStore.Get(ctx, "route1")
	if !ok {
		t.Fatal("Route should still exist")
	}
	found := false
	for _, m := range rt.Middlewares {
		if m == mwID {
			found = true
			break
		}
	}
	if found {
		t.Error("Middleware should have been removed from route")
	}
	if len(rt.Middlewares) != 1 || rt.Middlewares[0] != "other-mw" {
		t.Errorf("Route middlewares should have been updated, got %v", rt.Middlewares)
	}
}

func TestShadowedRouteDetection(t *testing.T) {
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{
			SecurityThreatThreshold: 30.0,
		},
	}, nil)
	ctx := t.Context()

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
