package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"golang.org/x/time/rate"
)

func TestLoginRateLimit(t *testing.T) {
	uiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("UI"))
	})
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxy"))
	})
	globalReg := &mockGlobalReg{
		config: &gateonv1.GlobalConfig{
			Auth: &gateonv1.AuthConfig{Enabled: true},
			Management: &gateonv1.ManagementConfig{
				AllowPublicManagement: true,
			},
		},
	}

	// Rate limit: 2 per minute for testing, burst 2
	loginLimiter := middleware.NewRateLimiter(rate.Every(time.Minute/2), 2)

	deps := BaseHandlerDeps{
		ProxyHandler: proxyHandler,
		RouteStore:   &mockRouteStore{},
		GlobalReg:    globalReg,
		LoginLimiter: loginLimiter,
		Auth:         nil, // Not needed for rate limit check
	}

	handler := CreateBaseHandler(uiHandler, deps, nil, http.NewServeMux())

	tests := []struct {
		name string
		path string
	}{
		{
			name: "REST Login",
			path: "/v1/login",
		},
		{
			name: "gRPC-Web Login",
			path: "/gateon.v1.ApiService/Login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset limiter for each test case by creating a new one
			deps.LoginLimiter = middleware.NewRateLimiter(rate.Every(time.Minute/2), 2)
			handler = CreateBaseHandler(uiHandler, deps, nil, http.NewServeMux())

			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("POST", tt.path, nil)
				req.RemoteAddr = "1.2.3.4:1234"
				ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
				req = req.WithContext(ctx)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					t.Fatalf("Attempt %d: expected status 200, got %d", i+1, rr.Code)
				}
			}

			// 3rd attempt should be rate limited
			req := httptest.NewRequest("POST", tt.path, nil)
			req.RemoteAddr = "1.2.3.4:1234"
			ctx := context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("Attempt 3: expected status 429, got %d", rr.Code)
			}
		})
	}
}
