// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package tests

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/stretchr/testify/assert"
)

func TestSecurityE2E(t *testing.T) {
	// Initialize telemetry store with a real file and ensure it's clean
	dbPath := filepath.Join(t.TempDir(), "security_e2e_test.db")
	err := telemetry.InitPathStatsStore("sqlite:"+dbPath, 1)
	assert.NoError(t, err)
	defer telemetry.ClosePathStatsStore(context.Background())

	// Define a simple backend
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with security middleware
	// We'll use the AdvancedSecurity Recognition which includes our new scanners
	handler := middleware.ThreatRecognition("test-route")(backend)

	tests := []struct {
		name           string
		method         string
		url            string
		body           string
		expectedThreat bool
		threatType     string
	}{
		{
			name:           "Clean Request",
			method:         "GET",
			url:            "/health",
			expectedThreat: false,
		},
		{
			name:           "Online Gambling Detection",
			method:         "GET",
			url:            "/search?q=online+casino+betting",
			expectedThreat: true,
			threatType:     "gambling_detected",
		},
		{
			name:           "Malicious JS Detection",
			method:         "POST",
			url:            "/submit",
			body:           "<script>eval(atob('YWxlcnQoMSk='))</script>",
			expectedThreat: true,
			threatType:     "generic_attack", // from genericAttackScanner
		},
		{
			name:           "PHP Vulnerability Detection",
			method:         "GET",
			url:            "/index.php?file=../../etc/passwd&cmd=system('id')",
			expectedThreat: true,
			threatType:     "php_vulnerability",
		},
		{
			name:           "Arbitrary File Upload Detection",
			method:         "POST",
			url:            "/upload?name=shell.php",
			expectedThreat: true,
			threatType:     "file_upload_attempt",
		},
		{
			name:           "Vulnerable Code Patterns",
			method:         "POST",
			url:            "/api",
			body:           "{\"code\": \"String.fromCharCode(88,83,83)\"}",
			expectedThreat: true,
			threatType:     "generic_attack",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, tc.url, bodyReader)
			if tc.method == "POST" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			// Wait longer for async telemetry recording (loop flushes every 2s for standard profile)
			time.Sleep(2500 * time.Millisecond)

			// Check if threat was recorded
			threats := telemetry.GetSecurityThreats(context.Background(), 50, 0, nil)
			found := false
			for _, th := range threats {
				if th.Type == tc.threatType && strings.Contains(th.RequestURI, tc.url) {
					found = true
					break
				}
			}

			if tc.expectedThreat {
				assert.True(t, found, "Expected threat %s not found in telemetry for %s", tc.threatType, tc.url)
			} else {
				assert.False(t, found, "Unexpected threat %s found in telemetry for %s", tc.threatType, tc.url)
			}
		})
	}
}
