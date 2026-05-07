package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	// IP Reputation usually needs data to work.
	// In CRS, it might be checking against some variables that are not set here.
	// However, we can check if it blocks if we manually set the reputation variables via Directives.
	mw, err := WAF(WAFConfig{
		UseCRS:             true,
		EnableIPReputation: true,
		// Set the flag in phase 1, and the rule in waf.go is also phase 1.
		// To ensure the flag is set before it's checked, we can use a lower ID or just a different phase.
		// However, Coraza processed directives in order.
		// Let's try to use a header to trigger it and check in phase 2.
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
