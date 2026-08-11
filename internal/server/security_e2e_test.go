// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestIntegration_Alerting(t *testing.T) {
	// 1. Setup mock webhook server
	var receivedThreat telemetry.SecurityThreat
	var receivedCount int
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedCount++
		body, _ := io.ReadAll(r.Body)
		var t telemetry.SecurityThreat
		_ = json.Unmarshal(body, &t)
		receivedThreat = t
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// 2. Initialize Alerting Manager with mock webhook
	cfg := &gateonv1.AlertingConfig{
		Enabled: true,
		Dispatchers: []*gateonv1.AlertDispatcher{
			{
				Id:         "test-webhook",
				Type:       "webhook",
				WebhookUrl: ts.URL,
			},
		},
		Playbooks: []*gateonv1.AlertPlaybook{
			{
				Id:            "test-playbook",
				Name:          "Test Playbook",
				EventType:     "all",
				Threshold:     0,
				DispatcherIds: []string{"test-webhook"},
			},
		},
	}
	alerting.Init(cfg, nil)
	defer alerting.UpdateConfig(&gateonv1.AlertingConfig{Enabled: false}, nil)

	t.Run("Positive - Alert Sent", func(t *testing.T) {
		receivedCount = 0
		threat := &telemetry.SecurityThreat{
			ID:       "test-threat-1",
			Type:     "waf_violation",
			SourceIP: "1.1.1.1",
			Score:    10,
		}
		alerting.HandleThreat(threat)

		// Wait for async alert delivery
		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			count := receivedCount
			mu.Unlock()
			if count > 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		mu.Lock()
		count := receivedCount
		threatID := receivedThreat.ID
		mu.Unlock()

		if count != 1 {
			t.Errorf("Expected 1 alert, got %d", count)
		}
		if threatID != threat.ID {
			t.Errorf("Expected threat ID %s, got %s", threat.ID, threatID)
		}
	})

	t.Run("Negative - Alerting Disabled", func(t *testing.T) {
		alerting.UpdateConfig(&gateonv1.AlertingConfig{Enabled: false}, nil)
		mu.Lock()
		receivedCount = 0
		mu.Unlock()
		threat := &telemetry.SecurityThreat{
			ID:   "test-threat-2",
			Type: "waf_violation",
		}
		alerting.HandleThreat(threat)

		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		count := receivedCount
		mu.Unlock()
		if count != 0 {
			t.Errorf("Expected 0 alerts when disabled, got %d", count)
		}
	})
}

func TestIntegration_SecurityHub(t *testing.T) {
	// 1. Setup telemetry store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "gateon_test.db")
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())

	// 2. Setup Server
	_, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	t.Run("Incidents and Threat Explorer", func(t *testing.T) {
		// Simulate threats
		threats := []telemetry.SecurityThreat{
			{ID: "t1", Type: "waf_violation", Category: "injection", Severity: "high", SourceIP: "1.2.3.4", Time: time.Now()},
			{ID: "t2", Type: "bruteforce", Category: "auth", Severity: "medium", SourceIP: "1.2.3.5", Time: time.Now()},
		}
		for _, th := range threats {
			telemetry.RecordSecurityThreat(th)
		}

		// Wait for batch flush
		time.Sleep(1500 * time.Millisecond)

		// Verify via telemetry.GetSecurityThreats (which is what the API uses)
		ctx := context.Background()
		filter := &telemetry.ThreatFilter{Status: "all"}
		results := telemetry.GetSecurityThreats(ctx, 10, 0, filter)

		if len(results) < 2 {
			t.Errorf("Expected at least 2 threats, got %d", len(results))
		}

		foundT1 := false
		foundT2 := false
		for _, r := range results {
			if r.ID == "t1" {
				foundT1 = true
			}
			if r.ID == "t2" {
				foundT2 = true
			}
		}
		if !foundT1 || !foundT2 {
			t.Errorf("Could not find both threats in Security Hub. T1: %v, T2: %v", foundT1, foundT2)
		}
	})
}

func TestIntegration_DistributedTracing(t *testing.T) {
	// 1. Setup telemetry store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "tracing_test.db")
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())

	// 2. Record a trace manually (as if from middleware)
	traceID := "trace-123"
	telemetry.RecordTrace(traceID, "GET /api", "service-1", "route-1", 50.0, time.Now(), "200", "/api", "127.0.0.1", "", "US", "UA", "GET", "", "/api", "", "", nil, nil, "", 1.0, 0, 0, 0, 0)

	// Wait for batch flush
	time.Sleep(1500 * time.Millisecond)

	// 3. Retrieve trace
	traces := telemetry.GetTraces(context.Background(), 10)
	found := false
	for _, tr := range traces {
		if tr.ID == traceID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Trace %s not found in store", traceID)
	}
}

func TestIntegration_CORSViolation(t *testing.T) {
	// 1. Setup mock backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// 2. Setup Server with CORS middleware
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cors_test.db")
	_ = telemetry.ClosePathStatsStore(context.Background())
	_ = telemetry.InitPathStatsStore("sqlite://"+dbPath, 7)
	defer telemetry.ClosePathStatsStore(context.Background())

	s, _ := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)

	_ = s.ServiceStore.Update(context.Background(), &gateonv1.Service{
		Id: "cors-svc", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	})
	_ = s.MwStore.Update(context.Background(), &gateonv1.Middleware{
		Id: "cors-mw", Name: "cors-mw", Type: "cors",
		Config: map[string]string{
			"allowed_origins": "http://allowed.com",
		},
	})
	_ = s.RouteStore.Update(context.Background(), &gateonv1.Route{
		Id: "cors-route", ServiceId: "cors-svc", Rule: "PathPrefix(`/`)", Type: "http",
		Middlewares: []string{"cors-mw"},
	})

	// 3. Handle request
	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, nil, nil, http.NewServeMux())
	})

	// Wrap with RequestState to ensure RouteID is captured
	chain := middleware.WithRequestState("test-ep", "test", false)
	finalHandler := chain(gatewayHandler)

	t.Run("Invalid Origin Detected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/foo", nil)
		req.Header.Set("Origin", "http://malicious.com")
		w := httptest.NewRecorder()
		finalHandler.ServeHTTP(w, req)

		// Wait for async threat recording
		time.Sleep(1500 * time.Millisecond)

		results := telemetry.GetSecurityThreats(context.Background(), 10, 0, &telemetry.ThreatFilter{Status: "all"})
		found := false
		for _, th := range results {
			if th.Type == "cors_violation" && strings.Contains(th.Details, "http://malicious.com") {
				found = true
				break
			}
		}
		if !found {
			t.Error("CORS violation from malicious.com not found in telemetry")
		}
	})

	t.Run("Valid Origin Allowed", func(t *testing.T) {
		// Clear threats by resetting store if possible, or just check count increase
		before := len(telemetry.GetSecurityThreats(context.Background(), 100, 0, &telemetry.ThreatFilter{Status: "all"}))

		req := httptest.NewRequest("GET", "http://localhost/foo", nil)
		req.Header.Set("Origin", "http://allowed.com")
		w := httptest.NewRecorder()
		finalHandler.ServeHTTP(w, req)

		time.Sleep(1500 * time.Millisecond)
		after := len(telemetry.GetSecurityThreats(context.Background(), 100, 0, &telemetry.ThreatFilter{Status: "all"}))

		if after > before {
			t.Errorf("Valid origin should not trigger a CORS violation. Count went from %d to %d", before, after)
		}
	})

	t.Run("Resolve CORS Violation", func(t *testing.T) {
		// 1. Trigger violation
		req := httptest.NewRequest("GET", "http://localhost/foo", nil)
		req.Header.Set("Origin", "http://new-allowed.com")
		w := httptest.NewRecorder()
		finalHandler.ServeHTTP(w, req)

		time.Sleep(1500 * time.Millisecond)

		// 2. Get the threat ID
		results := telemetry.GetSecurityThreats(context.Background(), 1, 0, &telemetry.ThreatFilter{Status: "all"})
		if len(results) == 0 || results[0].Type != "cors_violation" {
			t.Fatalf("CORS violation threat not found")
		}
		threatID := results[0].ID

		// 3. Resolve it via API
		l4Resolver := l4.NewResolver(s.RouteStore, s.ServiceStore)
		proxyInvalidator := NewServerProxyInvalidator(s, l4Resolver, s.RouteStore)
		apiSvc := api.NewApiService(api.ApiServiceConfig{
			Routes: s.RouteStore, Services: s.ServiceStore, Middlewares: s.MwStore,
			Invalidator: proxyInvalidator,
		})
		resp, err := apiSvc.ApplyRecommendation(context.Background(), &gateonv1.ApplyRecommendationRequest{
			AnomalyType: "cors_violation",
			ThreatId:    threatID,
		})

		if err != nil {
			t.Fatalf("ApplyRecommendation failed: %v", err)
		}
		if !resp.Success {
			t.Fatalf("ApplyRecommendation returned failure: %s", resp.Message)
		}

		// 4. Verify origin is now allowed
		mw, _ := s.MwStore.Get(context.Background(), "cors-mw")
		if !strings.Contains(mw.Config["allowed_origins"], "http://new-allowed.com") {
			t.Errorf("Origin not added to allowed_origins: %s", mw.Config["allowed_origins"])
		}

		// 5. Verify request now passes without new violation
		before := len(telemetry.GetSecurityThreats(context.Background(), 100, 0, &telemetry.ThreatFilter{Status: "all"}))
		w2 := httptest.NewRecorder()
		finalHandler.ServeHTTP(w2, req)

		time.Sleep(1500 * time.Millisecond)
		after := len(telemetry.GetSecurityThreats(context.Background(), 100, 0, &telemetry.ThreatFilter{Status: "all"}))

		if after > before {
			t.Errorf("Request should now be allowed without triggering new violation")
		}
	})
}
