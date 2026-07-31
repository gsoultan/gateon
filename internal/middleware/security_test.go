package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestWAF_AuditLogAndBodyLimits(t *testing.T) {
	// Minimal WAF with body limit and custom rule
	mw, err := WAF(WAFConfig{
		UseCRS:           false,
		RequestBodyLimit: 10, // Very small limit
		Directives:       `SecRule ARGS "blockme" "id:1,deny,status:403"`,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Check body limit
	req := httptest.NewRequest("POST", "/", strings.NewReader("this is a very long body that should be blocked"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body limit: expected error code (403/413), got %d", rr.Code)
	}

	// 2. Check rule match
	req = httptest.NewRequest("GET", "/?test=blockme", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("rule match: expected 403, got %d", rr.Code)
	}
}

type mockEbpfManager struct {
	shunnedIP string
}

func (m *mockEbpfManager) ShunIP(ip string) error                                       { m.shunnedIP = ip; return nil }
func (m *mockEbpfManager) UnshunIP(ip string) error                                     { return nil }
func (m *mockEbpfManager) BlockCountry(countryCode string) error                        { return nil }
func (m *mockEbpfManager) UpdateManagementWhitelist(ips []string) error                 { return nil }
func (m *mockEbpfManager) SetPortKnockingSequence(seq []int32) error                    { return nil }
func (m *mockEbpfManager) Start(ctx context.Context)                                    {}
func (m *mockEbpfManager) UpdateLoadBalancerBackends(ips []string) error                { return nil }
func (m *mockEbpfManager) SetAdaptiveRateLimit(ip string, interval time.Duration) error { return nil }
func (m *mockEbpfManager) ShunJA4(ja4Fingerprint string) error                          { return nil }
func (m *mockEbpfManager) BlocklistCuckoo(key string) error                             { return nil }
func (m *mockEbpfManager) GetTopIPs(limit int) ([]ebpf.IPStat, error)                   { return nil, nil }
func (m *mockEbpfManager) GetMapStats() (ebpf.MapStats, error)                          { return ebpf.MapStats{}, nil }

type telemetryMockWrapper struct {
	*mockEbpfManager
}

func (w *telemetryMockWrapper) GetTopIPs(limit int) ([]telemetry.IPStat, error) { return nil, nil }

func TestWAF_Shunning(t *testing.T) {
	// Initialize telemetry store for escalation logic
	dbPath := "gateon_shun_test.db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	_ = telemetry.InitPathStatsStore(dbPath, 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	mockEbpf := &mockEbpfManager{}
	// Note: In the new architecture, WAF doesn't call EbpfManager directly.
	// It calls telemetry.RecordSecurityThreat, which triggers escalation.
	// We need to set the global eBPF manager for telemetry to use.
	telemetry.SetEbpfManager(&telemetryMockWrapper{mockEbpf})

	mw, err := WAF(WAFConfig{
		UseCRS:      false,
		EbpfManager: mockEbpf,
		Directives:  `SecRule ARGS "shunme" "id:1,deny,status:403,severity:CRITICAL"`,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ip := "1.2.3.4"
	// Simulate 3 attacks from different fingerprints
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest("GET", "/?test=shunme", nil)
		req.RemoteAddr = ip + ":1234"
		// Set unique JA4+ for each request to simulate different users
		ja4plus := "user-" + string(rune('0'+i)) + "_ge11nn0200_90c635b248af"
		rs := &request.RequestState{JA4Plus: ja4plus}
		req = req.WithContext(context.WithValue(req.Context(), request.RequestStateContextKey{}, rs))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("request %d: expected 403, got %d", i, rr.Code)
		}
	}

	// Wait for background worker to process threats and escalate to IP mitigation
	time.Sleep(200 * time.Millisecond)

	if mockEbpf.shunnedIP != ip {
		t.Errorf("expected IP %s to be shunned after 3 attacks, got %q", ip, mockEbpf.shunnedIP)
	}
}

func TestBotManagement_Challenge(t *testing.T) {
	secret := "test-secret"
	cfg := BotManagementConfig{
		Enabled:                 true,
		EnableJSChallenge:       true,
		ChallengeTimeoutSeconds: 3600,
		SecretKey:               secret,
	}
	mw := BotManagement(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. New request should get challenge
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for initial request, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Security Challenge") {
		t.Errorf("expected challenge in body. Got: %q", rr.Body.String())
	}

	// 2. Request with valid token should pass
	ip := "192.0.2.1"
	req.RemoteAddr = ip + ":1234"
	token := GenerateChallengeSeed(secret, "Mozilla/5.0", ip)
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = ip + ":1234"
	req.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: token})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", rr.Code)
	}

	// 3. Request with mismatched IP should fail
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "1.1.1.1:1234" // Different IP
	req.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: token})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 with mismatched IP, got %d", rr.Code)
	}
}
