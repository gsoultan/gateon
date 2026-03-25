package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestProxyHandler_Protocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		setup    func() (*httptest.Server, string)
	}{
		{
			name:     "HTTP/1.1",
			protocol: "HTTP/1.1",
			setup: func() (*httptest.Server, string) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("HTTP/1.1 response"))
				}))
				return s, s.URL
			},
		},
		{
			name:     "HTTP/2 Cleartext (h2c)",
			protocol: "h2c",
			setup: func() (*httptest.Server, string) {
				h2s := &http2.Server{}
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("h2c response"))
				})
				s := httptest.NewServer(h2c.NewHandler(handler, h2s))
				url := strings.Replace(s.URL, "http://", "h2c://", 1)
				return s, url
			},
		},
		{
			name:     "HTTP/2 TLS (h2)",
			protocol: "h2",
			setup: func() (*httptest.Server, string) {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("h2 response"))
				}))
				s.EnableHTTP2 = true
				s.StartTLS()
				url := strings.Replace(s.URL, "https://", "h2://", 1)
				return s, url
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, targetURL := tt.setup()
			defer backend.Close()

			rt := &gateonv1.Route{
				Id:        "test-route",
				Type:      "http",
				ServiceId: "test-service",
			}

			// Mock service registry
			svc := &gateonv1.Service{
				Id:   "test-service",
				Name: "test-service",
				WeightedTargets: []*gateonv1.Target{
					{Url: targetURL, Weight: 1},
				},
			}
			tmpDir := t.TempDir()
			servicePath := filepath.Join(tmpDir, "services.json")
			serviceReg := config.NewServiceRegistry(servicePath)
			_ = serviceReg.Update(context.Background(), svc)

			ph := NewProxyHandler(rt, serviceReg)
			defer ph.Close()

			req := httptest.NewRequest("GET", "http://localhost", nil)
			w := httptest.NewRecorder()
			ph.ServeHTTP(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			expected := tt.protocol + " response"
			if !strings.Contains(string(body), expected) {
				t.Errorf("%s: expected response to contain %q, got %q", tt.name, expected, string(body))
			}
		})
	}
}

func TestProxyHandler_WeightedLoadBalancing(t *testing.T) {
	// Setup two backends
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend2"))
	}))
	defer backend2.Close()

	svc := &gateonv1.Service{
		Id:                 "weighted-service",
		Name:               "weighted-service",
		LoadBalancerPolicy: "weighted_round_robin",
		WeightedTargets: []*gateonv1.Target{
			{Url: backend1.URL, Weight: 3}, // 3x more weight
			{Url: backend2.URL, Weight: 1},
		},
	}

	tmpDir := t.TempDir()
	servicePath := filepath.Join(tmpDir, "services.json")
	serviceReg := config.NewServiceRegistry(servicePath)
	_ = serviceReg.Update(context.Background(), svc)

	rt := &gateonv1.Route{
		Id:        "weighted-route",
		ServiceId: svc.Id,
	}

	ph := NewProxyHandler(rt, serviceReg)
	defer ph.Close()

	counts := make(map[string]int)
	for range 100 {
		req := httptest.NewRequest("GET", "http://localhost", nil)
		w := httptest.NewRecorder()
		ph.ServeHTTP(w, req)
		counts[w.Body.String()]++
	}

	// Expect approximately 75 for backend1 and 25 for backend2
	if counts["backend1"] < 60 || counts["backend1"] > 90 {
		t.Errorf("unexpected distribution: %v", counts)
	}
}
