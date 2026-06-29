package proxy

import (
	"net/http"
	"testing"
)

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "Standard WebSocket",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "Upgrade",
			},
			expected: true,
		},
		{
			name: "WebSocket without Connection",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			expected: true,
		},
		{
			name: "Non-WebSocket Upgrade",
			headers: map[string]string{
				"Upgrade": "h2c",
			},
			expected: true,
		},
		{
			name:     "No Upgrade",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name: "Connection Upgrade but no Upgrade header",
			headers: map[string]string{
				"Connection": "Upgrade",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "http://example.com", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := isUpgradeRequest(r); got != tt.expected {
				t.Errorf("isUpgradeRequest() = %v, want %v", got, tt.expected)
			}
		})
	}
}
