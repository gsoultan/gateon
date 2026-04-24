package telemetry

import (
	"net/http/httptest"
	"testing"
)

func TestGenerateFingerprint(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	req1.Header.Set("Accept-Language", "en-US")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Accept-Language", "en-US")

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("User-Agent", "Bot/1.0")

	fp1 := GenerateFingerprint(req1)
	fp2 := GenerateFingerprint(req2)
	fp3 := GenerateFingerprint(req3)

	if fp1.Hash != fp2.Hash {
		t.Errorf("Expected identical fingerprints for identical requests, got %s and %s", fp1.Hash, fp2.Hash)
	}

	if fp1.Hash == fp3.Hash {
		t.Errorf("Expected different fingerprints for different requests, got same hash %s", fp1.Hash)
	}
}
