package proxy

import "testing"

func TestBuildHealthCheckURL(t *testing.T) {
	tests := []struct {
		name                string
		targetURL           string
		healthCheckPath     string
		healthCheckPort     int32
		healthCheckProtocol string
		want                string
	}{
		{
			name:            "no overrides http",
			targetURL:       "http://backend:3000",
			healthCheckPath: "/healthz",
			want:            "http://backend:3000/healthz",
		},
		{
			name:            "port override only",
			targetURL:       "http://backend:3000",
			healthCheckPath: "/healthz",
			healthCheckPort: 3001,
			want:            "http://backend:3001/healthz",
		},
		{
			name:                "protocol override only",
			targetURL:           "h2c://backend:3000",
			healthCheckPath:     "/healthz",
			healthCheckProtocol: "http",
			want:                "http://backend:3000/healthz",
		},
		{
			name:                "both port and protocol override (grpc on 3000, http health on 3001)",
			targetURL:           "h2c://backend:3000",
			healthCheckPath:     "/healthz",
			healthCheckPort:     3001,
			healthCheckProtocol: "http",
			want:                "http://backend:3001/healthz",
		},
		{
			name:            "h2 scheme without overrides",
			targetURL:       "h2://backend:443",
			healthCheckPath: "/health",
			want:            "https://backend:443/health",
		},
		{
			name:            "h3 scheme without overrides",
			targetURL:       "h3://backend:443",
			healthCheckPath: "/health",
			want:            "https://backend:443/health",
		},
		{
			name:                "h2 scheme with port and protocol override",
			targetURL:           "h2://backend:443",
			healthCheckPath:     "/ready",
			healthCheckPort:     8080,
			healthCheckProtocol: "http",
			want:                "http://backend:8080/ready",
		},
		{
			name:            "no port in target url with port override",
			targetURL:       "http://backend",
			healthCheckPath: "/healthz",
			healthCheckPort: 3001,
			want:            "http://backend:3001/healthz",
		},
		{
			name:            "zero port means no override",
			targetURL:       "http://backend:3000",
			healthCheckPath: "/healthz",
			healthCheckPort: 0,
			want:            "http://backend:3000/healthz",
		},
		{
			name:                "empty protocol means no override",
			targetURL:           "http://backend:3000",
			healthCheckPath:     "/healthz",
			healthCheckProtocol: "",
			want:                "http://backend:3000/healthz",
		},
		{
			name:            "trailing slash stripped from target",
			targetURL:       "http://backend:3000/",
			healthCheckPath: "/healthz",
			healthCheckPort: 3001,
			want:            "http://backend:3001/healthz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &ProxyHandler{
				healthCheckPath:     tt.healthCheckPath,
				healthCheckPort:     tt.healthCheckPort,
				healthCheckProtocol: tt.healthCheckProtocol,
			}
			got := h.buildHealthCheckURL(tt.targetURL)
			if got != tt.want {
				t.Errorf("buildHealthCheckURL(%q) = %q, want %q", tt.targetURL, got, tt.want)
			}
		})
	}
}
