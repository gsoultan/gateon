package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

func TestIPReputationStore_IsBad(t *testing.T) {
	cfg := &gateonv1.IPReputationConfig{
		Enabled:  true,
		FeedUrls: []string{},
	}
	store := NewIPReputationStore(cfg)

	// Test with manual entry
	store.badIPs["1.2.3.4"] = 1.0

	bad, score := store.IsBad("1.2.3.4")
	assert.True(t, bad)
	assert.Equal(t, 1.0, score)

	bad, _ = store.IsBad("8.8.8.8")
	assert.False(t, bad)
}

func TestIPReputationStore_ExternalScore(t *testing.T) {
	// Mock AbuseIPDB API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-api-key", r.Header.Get("Key"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95}}`))
	}))
	defer server.Close()

	cfg := &gateonv1.IPReputationConfig{
		Enabled: true,
		Integrations: []*gateonv1.IPReputationIntegration{
			{
				Id:      "abuseipdb-1",
				Name:    "AbuseIPDB",
				Type:    "abuseipdb",
				ApiKey:  "test-api-key",
				Enabled: true,
			},
		},
	}
	store := NewIPReputationStore(cfg)

	// Override the URL in the client for testing
	for i := range store.integrations {
		if store.integrations[i].config.Type == "abuseipdb" {
			store.integrations[i].client.BaseURL = server.URL
		}
	}

	score, provider := store.GetExternalScore(context.Background(), "1.2.3.4")
	assert.Equal(t, 95, score)
	assert.Equal(t, "AbuseIPDB", provider)
}
