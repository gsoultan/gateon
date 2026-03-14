package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

func setupProxyTest(t *testing.T, routeType string, withGrpcWebMiddleware bool) (*Server, *atomic.Int64, *grpcweb.WrappedGrpcServer, *http.ServeMux) {
	t.Helper()
	tmpDir := t.TempDir()
	mwReg := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmpDir, "services.json"))),
		WithMiddlewareRegistry(mwReg),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmpDir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	hits := &atomic.Int64{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}))
	t.Cleanup(backend.Close)

	svc := &gateonv1.Service{
		Id: "svc",
		WeightedTargets: []*gateonv1.Target{
			{Url: backend.URL, Weight: 1},
		},
	}
	if err := s.ServiceStore.Update(context.Background(), svc); err != nil {
		t.Fatalf("update service: %v", err)
	}
	rt := &gateonv1.Route{
		Id: "route", ServiceId: svc.Id, Rule: "PathPrefix(`/`)", Type: routeType,
	}
	if withGrpcWebMiddleware {
		grpcwebMW := &gateonv1.Middleware{Id: "grpcweb-mw", Name: "grpcweb", Type: "grpcweb", Config: nil}
		if err := mwReg.Update(context.Background(), grpcwebMW); err != nil {
			t.Fatalf("update grpcweb middleware: %v", err)
		}
		rt.Middlewares = []string{"grpcweb-mw"}
	}
	if err := s.RouteStore.Update(context.Background(), rt); err != nil {
		t.Fatalf("update route: %v", err)
	}

	grpcServer := grpc.NewServer()
	t.Cleanup(grpcServer.Stop)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return s, hits, grpcweb.WrapServer(grpcServer), mux
}

func TestHandleProxyOrLocal_DoesNotProxyLegacyGrpcWebRouteType(t *testing.T) {
	s, hits, wrapped, mux := setupProxyTest(t, "grpc-web", false)
	req := httptest.NewRequest(http.MethodPost, "http://gateway/gateon.v1.ApiService/GetStatus", http.NoBody)
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	w := httptest.NewRecorder()
	s.HandleProxyOrLocal(w, req, wrapped, mux)
	if got := hits.Load(); got != 0 {
		t.Fatalf("expected legacy grpc-web route type to be ignored, proxied requests = %d", got)
	}
}

func TestHandleProxyOrLocal_ProxiesGrpcWebRequestsForGrpcRouteWithMiddleware(t *testing.T) {
	s, hits, wrapped, mux := setupProxyTest(t, "grpc", true)
	req := httptest.NewRequest(http.MethodPost, "http://gateway/gateon.v1.ApiService/GetStatus", http.NoBody)
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	w := httptest.NewRecorder()
	s.HandleProxyOrLocal(w, req, wrapped, mux)
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected grpc route with grpcweb middleware to proxy grpc-web request exactly once, got %d", got)
	}
}

func TestHandleProxyOrLocal_GrpcWebWithoutMiddlewareReturns415(t *testing.T) {
	s, _, wrapped, mux := setupProxyTest(t, "grpc", false)
	req := httptest.NewRequest(http.MethodPost, "http://gateway/gateon.v1.ApiService/GetStatus", http.NoBody)
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	w := httptest.NewRecorder()
	s.HandleProxyOrLocal(w, req, wrapped, mux)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 when grpc route has no grpcweb middleware, got %d", w.Code)
	}
	if body := w.Body.String(); body != "gRPC-Web requires the grpcweb middleware on this route" {
		t.Fatalf("expected specific error message, got %q", body)
	}
}
