package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

func TestIntegration_ProxyRedirects(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-internal":
			http.Redirect(w, r, "/new-path", http.StatusFound)
		case "/redirect-external":
			http.Redirect(w, r, "http://example.com/external", http.StatusFound)
		case "/new-path":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Target reached"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()

	tmpDir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmpDir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmpDir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	svc := &gateonv1.Service{
		Id: "test-service", Name: "test-service",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}
	_ = s.ServiceStore.Update(t.Context(), svc)
	rt := &gateonv1.Route{
		Id: "test-route", ServiceId: svc.Id, Rule: "PathPrefix(`/`)", Type: "http",
	}
	_ = s.RouteStore.Update(t.Context(), rt)

	grpcServer := grpc.NewServer()
	apiService := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore,
		TLSManager: s.TLSManager,
	})
	gateonv1.RegisterApiServiceServer(grpcServer, apiService)
	wrapped := grpcweb.WrapServer(grpcServer)
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, apiService, handlerDeps(s))

	gatewayHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, wrapped, mux)
	})

	t.Run("InternalRedirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/redirect-internal", nil)
		w := httptest.NewRecorder()
		gatewayHandler.ServeHTTP(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("expected status 302, got %v", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if loc != "/new-path" {
			t.Errorf("expected Location '/new-path', got %q", loc)
		}

		// Follow the redirect
		req2 := httptest.NewRequest("GET", "http://localhost"+loc, nil)
		w2 := httptest.NewRecorder()
		gatewayHandler.ServeHTTP(w2, req2)
		resp2 := w2.Result()
		body, _ := io.ReadAll(resp2.Body)
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("expected status 200 after redirect, got %v", resp2.StatusCode)
		}
		if string(body) != "Target reached" {
			t.Errorf("expected body 'Target reached', got %q", string(body))
		}
	})

	t.Run("ExternalRedirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/redirect-external", nil)
		w := httptest.NewRecorder()
		gatewayHandler.ServeHTTP(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("expected status 302, got %v", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if loc != "http://example.com/external" {
			t.Errorf("expected Location 'http://example.com/external', got %q", loc)
		}
	})
}
