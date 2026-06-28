package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestWAF_IPReputationIntegration(t *testing.T) {
	// 1. Setup Reputation Store
	repCfg := &gateonv1.IPReputationConfig{
		Enabled:        true,
		BlockThreshold: 0.8, // 80%
	}
	repStore := reputation.NewIPReputationStore(repCfg)

	// Set 1.2.3.4 as a bad IP with score 0.9 (should be blocked)
	repStore.SetIPScore("1.2.3.4", 0.9)
	// Set 5.6.7.8 as a suspicious IP with score 0.5 (should be flagged but not blocked)
	repStore.SetIPScore("5.6.7.8", 0.5)

	// 2. Setup WAF via Factory
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{
			Enabled:      true,
			UseCrs:       true,
			IpReputation: true,
		},
	}}
	f := NewFactory(nil, store, nil, repStore, ".")

	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name              string
		remoteAddr        string
		expectCode        int
		expectScoreHeader string
	}{
		{
			name:       "clean IP allowed",
			remoteAddr: "9.9.9.9",
			expectCode: http.StatusOK,
		},
		{
			name:              "blocked IP denied",
			remoteAddr:        "1.2.3.4",
			expectCode:        http.StatusForbidden,
			expectScoreHeader: "0.90",
		},
		{
			name:              "suspicious IP allowed but flagged",
			remoteAddr:        "5.6.7.8",
			expectCode:        http.StatusOK,
			expectScoreHeader: "0.50",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr + ":1234"
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectCode {
				t.Errorf("%s: expected status %d, got %d", tc.name, tc.expectCode, rr.Code)
			}
		})
	}
}

func TestWAF_RouteSpecificReputationIntegration(t *testing.T) {
	// 1. Setup Reputation Store
	repCfg := &gateonv1.IPReputationConfig{
		Enabled:        true,
		BlockThreshold: 0.8,
	}
	repStore := reputation.NewIPReputationStore(repCfg)
	repStore.SetIPScore("1.2.3.4", 0.9)

	// 2. Setup Factory
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}
	f := NewFactory(nil, store, nil, repStore, ".")

	// 3. Route-specific WAF config via Middleware proto
	m := &gateonv1.Middleware{
		Type: "waf",
		Config: map[string]string{
			"enabled":       "true",
			"ip_reputation": "true",
		},
	}

	mw, err := f.Create(m, "test-route")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status %d for blocked IP, got %d", http.StatusForbidden, rr.Code)
	}
}
