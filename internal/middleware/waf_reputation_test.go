package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAF_FalsePositiveReproduction(t *testing.T) {
	mw, err := WAF(WAFConfig{
		UseCRS:        true,
		ParanoiaLevel: 1,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/v1/employees/refresh-token", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpZCI6IjE3YTU1ODYyLTBlZTAtMTFlZC04NjFkLTAyNDJhYzEyMDAwMiIsImV4cCI6MTc4MjkwOTE4OH0.jqcuyYZf4WRBQD9NB27A9a0qq5-Fk-JoxtutT0WX1Mv_YJZZJpwNcbEelHeATgeB")
	req.Header.Set("X-Api-Key", "$apr1$Yd0EG8pw$q3.nf5Jnk6Y.nUje/4D3f0")
	req.Header.Set("X-Gateon-Reputation", "100.00")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Currently, this is expected to FAIL (return 403) based on the issue description.
	// We want it to PASS (return 200).
	if rr.Code != http.StatusOK {
		t.Errorf("WAF blocked a legitimate request with reputation 100: got status %d, want %d", rr.Code, http.StatusOK)
	}
}
