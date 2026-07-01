package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

func TestWAF_AdvancedSecurityRules(t *testing.T) {
	// Initialize a test store with the new rules
	d, dialect, _ := db.Open("sqlite::memory:")
	_ = db.Migrate(d, dialect)

	store := waf.NewStore(d)
	// Seed the rules into the test store
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}

	mw, err := WAF(WAFConfig{
		UseCRS:                    true,
		EnableIPReputation:        true,
		EnableDOSProtection:       true,
		EnableMalwareDetection:    true,
		EnableRansomwareDetection: true,
		EnableDLP:                 true,
		EnableResponseInspection:  true,
		WafRules:                  store,
		ResponseBodyLimit:         1024 * 1024,
		RequestBodyLimit:          1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dlp-test" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User data leak: 4111111111111111"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		headers    map[string]string
		expectCode int
	}{
		{
			name:       "Scanner Detection (Nikto)",
			method:     "GET",
			url:        "/",
			headers:    map[string]string{"User-Agent": "Nikto/2.1.6"},
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Scanner Detection (sqlmap)",
			method:     "GET",
			url:        "/",
			headers:    map[string]string{"User-Agent": "sqlmap/1.4.11#stable"},
			expectCode: http.StatusForbidden,
		},
		{
			name:       "SQLi Blind Injection",
			method:     "GET",
			url:        "/?id=1%27+AND+(SELECT+1+FROM+(SELECT(SLEEP(5)))a)--",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "XSS Injection",
			method:     "GET",
			url:        "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Shellshock Attempt",
			method:     "GET",
			url:        "/",
			headers:    map[string]string{"User-Agent": "() { :;}; echo VULNERABLE"},
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Ransomware Note Search",
			method:     "GET",
			url:        "/README_FOR_DECRYPT.txt",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Malicious Web Shell Search",
			method:     "GET",
			url:        "/c99.php",
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			req.Header.Set("X-Gateon-Test-Reputation", "0") // Force low threshold (5)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("%s: expected status %d, got %d", tc.name, tc.expectCode, rr.Code)
			}
		})
	}

	t.Run("DLP Detection", func(t *testing.T) {
		// DLP rule 130000 is disabled by default in Seed. Enable it for this test.
		err := store.UpdateRule(t.Context(), &waf.Rule{
			ID:            "130000",
			Name:          "DLP: Credit Card Number Detection",
			Directive:     `SecRule RESPONSE_BODY "@rx \b4[0-9]{12}(?:[0-9]{3})?\b" "id:130000,phase:4,deny,status:403,msg:'Credit card number detected in response',tag:'dlp',tag:'compliance',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "DLP",
		})
		if err != nil {
			t.Fatalf("failed to enable DLP rule: %v", err)
		}

		// Re-initialize WAF to load the enabled rule
		mw, _ := WAF(WAFConfig{
			UseCRS:                   true,
			EnableDLP:                true,
			EnableResponseInspection: true,
			WafRules:                 store,
			ResponseBodyLimit:        1024 * 1024,
		})
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User data leak: 4111111111111111"))
		}))

		req := httptest.NewRequest("GET", "/dlp-test", nil)
		// Use a neutral reputation (50) to pass the phase 1 auto-blocking (rule 910002)
		// but still be subject to standard WAF rules.
		req.Header.Set("X-Gateon-Test-Reputation", "50")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403 (DLP), got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})
}
