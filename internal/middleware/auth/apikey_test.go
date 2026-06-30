package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyValidator_MultiKey(t *testing.T) {
	keys := map[string]string{
		"secret1": "tenant1",
		"secret2": "tenant2",
		"secret3": "tenant3",
	}
	store := NewMemoryAPIKeyStore(keys, false)
	validator := NewAPIKeyValidator(store, "X-API-Key", "", AuthBaseConfig{})

	tests := []struct {
		name           string
		apiKey         string
		expectedStatus int
		expectedTenant string
	}{
		{
			name:           "Valid Key 1",
			apiKey:         "secret1",
			expectedStatus: http.StatusOK,
			expectedTenant: "tenant1",
		},
		{
			name:           "Valid Key 2",
			apiKey:         "secret2",
			expectedStatus: http.StatusOK,
			expectedTenant: "tenant2",
		},
		{
			name:           "Valid Key 3",
			apiKey:         "secret3",
			expectedStatus: http.StatusOK,
			expectedTenant: "tenant3",
		},
		{
			name:           "Invalid Key",
			apiKey:         "wrong-secret",
			expectedStatus: http.StatusUnauthorized,
			expectedTenant: "",
		},
		{
			name:           "Missing Key",
			apiKey:         "",
			expectedStatus: http.StatusUnauthorized,
			expectedTenant: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}

			rr := httptest.NewRecorder()
			handler := validator.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tenantID, ok := r.Context().Value(TenantIDContextKey).(string)
				if !ok {
					t.Error("Tenant ID not found in context")
				}
				if tenantID != tc.expectedTenant {
					t.Errorf("Expected tenant %s, got %s", tc.expectedTenant, tenantID)
				}
				w.WriteHeader(http.StatusOK)
			}))

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}
		})
	}
}

func TestAPIKeyValidator_Hashed(t *testing.T) {
	apiKey := "secret1"
	hash := sha256.Sum256([]byte(apiKey))
	hashStr := hex.EncodeToString(hash[:])

	keys := map[string]string{
		hashStr: "tenant1",
	}
	store := NewMemoryAPIKeyStore(keys, true)
	validator := NewAPIKeyValidator(store, "X-API-Key", "", AuthBaseConfig{})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", apiKey)

	rr := httptest.NewRecorder()
	handler := validator.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Hash used: %s", rr.Code, hashStr)
	}
}
