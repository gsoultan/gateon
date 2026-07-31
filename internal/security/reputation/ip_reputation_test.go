package reputation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestIPReputationStore_CIDRMatch(t *testing.T) {
	cfg := &gateonv1.IPReputationConfig{
		Enabled: true,
	}
	store := NewIPReputationStore(cfg)

	// Test IPv4 CIDR
	prefix, _ := netip.ParsePrefix("192.168.1.0/24")
	store.trie.insert(prefix, 1.0)

	bad, score := store.IsBad("192.168.1.50")
	assert.True(t, bad)
	assert.Equal(t, 1.0, score)

	bad, _ = store.IsBad("192.168.2.1")
	assert.False(t, bad)

	// Test IPv6 CIDR
	prefix6, _ := netip.ParsePrefix("2001:db8::/32")
	store.trie.insert(prefix6, 0.8)

	bad, score = store.IsBad("2001:db8::1")
	assert.True(t, bad)
	assert.Equal(t, 0.8, score)

	bad, _ = store.IsBad("2001:db9::1")
	assert.False(t, bad)
}

func BenchmarkIPTrie_Lookup(b *testing.B) {
	trie := newIPTrie()
	// Insert 1000 prefixes
	for i := 0; i < 255; i++ {
		p, _ := netip.ParsePrefix(fmt.Sprintf("10.%d.0.0/16", i))
		trie.insert(p, float64(i))
	}
	addr, _ := netip.ParseAddr("10.123.45.67")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.search(addr)
	}
}

func TestIPReputationStore_FetchFeed(t *testing.T) {
	// Mock feed server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# Comment line\n" +
			"1.2.3.4\n" +
			"5.6.7.8 # Inline comment\n" +
			"192.168.0.0/24\n" +
			"2001:db8::/32\n" +
			"\n"))
	}))
	defer server.Close()

	cfg := &gateonv1.IPReputationConfig{
		Enabled:  true,
		FeedUrls: []string{server.URL},
	}
	store := NewIPReputationStore(cfg)
	// Reconfigure will trigger an update in background, but we can call it manually for synchronous test
	store.update(context.Background())

	// Test exact IPs
	bad, _ := store.IsBad("1.2.3.4")
	assert.True(t, bad)
	bad, _ = store.IsBad("5.6.7.8")
	assert.True(t, bad)

	// Test IPv4 CIDR
	bad, _ = store.IsBad("192.168.0.100")
	assert.True(t, bad)

	// Test IPv6 CIDR
	bad, _ = store.IsBad("2001:db8::abcd")
	assert.True(t, bad)

	// Test clean IP
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
		if client, ok := store.integrations[i].client.(*AbuseIPDBClient); ok {
			client.BaseURL = server.URL
		}
	}

	score, provider := store.GetExternalScore(context.Background(), "1.2.3.4")
	assert.Equal(t, 95, score)
	assert.Equal(t, "AbuseIPDB", provider)
}
