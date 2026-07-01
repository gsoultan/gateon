package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

func TestWAF_PHPAttacks(t *testing.T) {
	mw, err := WAF(WAFConfig{
		UseCRS:     true,
		DisablePHP: false,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		body       string
		expectCode int
	}{
		{
			name:       "Safe request",
			method:     "GET",
			url:        "/?name=test",
			expectCode: http.StatusOK,
		},
		{
			name:       "PHP injection in query",
			method:     "GET",
			url:        "/?test=%3C%3Fphp%20system('id')%3B%20%3F%3E",
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestWAF_NodeJSAttacks(t *testing.T) {
	mw, err := WAF(WAFConfig{
		UseCRS:        true,
		DisableNodeJS: false,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		body       string
		expectCode int
	}{
		{
			name:       "NodeJS/Generic injection in query",
			method:     "GET",
			url:        "/?test=process.env",
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestWAF_IPReputation(t *testing.T) {
	// Initialize a test store with the IP reputation rule
	d, _, _ := db.Open("sqlite::memory:")
	// Manually create table for test
	_, _ = d.Exec(`CREATE TABLE waf_rules (id TEXT PRIMARY KEY, name TEXT, directive TEXT, enabled INTEGER, paranoia_level INTEGER, category TEXT, created_at DATETIME, updated_at DATETIME)`)

	store := waf.NewStore(d)
	_ = store.AddRule(t.Context(), &waf.Rule{
		ID:            "910001",
		Name:          "IP Reputation Blocking",
		Directive:     `SecRule TX:ip_reputation_block_flag "@eq 1" "id:910001,phase:2,deny,status:403,msg:'IP Reputation block',tag:'reputation',severity:CRITICAL"`,
		Enabled:       true,
		ParanoiaLevel: 1,
		Category:      "Reputation",
	})

	mw, err := WAF(WAFConfig{
		UseCRS:             true,
		EnableIPReputation: true,
		WafRules:           store,
		// Set the flag in phase 1, and the rule in waf.go is also phase 1.
		Directives: `SecRule REQUEST_HEADERS:X-Block-Me "@eq 1" "id:2000,phase:1,nolog,pass,setvar:tx.ip_reputation_block_flag=1"`,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Block-Me", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403 (IP Reputation), got %d", rr.Code)
	}
}
