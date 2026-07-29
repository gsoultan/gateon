package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type mockApiService struct {
	gateonv1.UnimplementedApiServiceServer
}

func (s *mockApiService) GetStatus(ctx context.Context, req *gateonv1.GetStatusRequest) (*gateonv1.GetStatusResponse, error) {
	return &gateonv1.GetStatusResponse{
		Status:  "OK",
		Version: "1.0.0",
	}, nil
}

func TestGRPCWeb_E2E(t *testing.T) {
	// 1. Setup Backend gRPC Server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	mockSvc := &mockApiService{}
	gateonv1.RegisterApiServiceServer(grpcServer, mockSvc)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("grpc server finished: %v", err)
		}
	}()
	defer grpcServer.Stop()

	backendAddr := "h2c://" + lis.Addr().String()

	// 2. Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: backendAddr, Weight: 1}},
	})

	// Configure Middleware
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "grpcweb-mw",
		Type: "grpcweb",
		Config: map[string]string{
			"allowed_origins": "*",
		},
	})

	// Configure Route
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:          "grpc-route",
		ServiceId:   "grpc-svc",
		Rule:        "PathPrefix(`/gateon.v1.ApiService`)",
		Type:        "grpc", // or "grpc-web"
		Middlewares: []string{"grpcweb-mw"},
	})

	// 3. Prepare gRPC-Web Request
	// Method: /gateon.v1.ApiService/GetStatus
	reqMsg := &gateonv1.GetStatusRequest{}
	reqData, err := proto.Marshal(reqMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	// gRPC frame: [flag(1)] [len(4)] [data]
	frame := make([]byte, 5+len(reqData))
	frame[0] = 0 // data frame
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(reqData)))
	copy(frame[5:], reqData)

	req := httptest.NewRequest("POST", "http://localhost/gateon.v1.ApiService/GetStatus", bytes.NewReader(frame))
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")
	req.Header.Set("Origin", "http://localhost:3000")

	// 4. Handle Request
	w := httptest.NewRecorder()

	// We need to bypass actual proxying to the network if we want to use httptest.NewRecorder
	// But since we started a real TCP listener for gRPC, Gateon will try to connect to it.
	// Gateon's proxy uses http.DefaultTransport which can connect to our listener.

	// Use the server's handler
	mux := http.NewServeMux() // dummy mux for internal API
	s.HandleProxyOrLocal(w, req, nil, mux)

	// 5. Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Verify Content-Type
	if ct := resp.Header.Get("Content-Type"); ct != "application/grpc-web" {
		t.Errorf("expected Content-Type application/grpc-web, got %q", ct)
	}

	// Verify CORS headers
	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: *, got %q", origin)
	}

	// Parse Response Frames
	// Response should have at least two frames: one for data, one for trailers (gRPC-Web)
	offset := 0
	foundData := false
	foundTrailers := false

	for offset < len(body) {
		if offset+5 > len(body) {
			t.Errorf("unexpected end of body at offset %d", offset)
			break
		}
		flag := body[offset]
		length := binary.BigEndian.Uint32(body[offset+1 : offset+5])
		offset += 5

		if offset+int(length) > len(body) {
			t.Errorf("frame length %d exceeds remaining body size at offset %d", length, offset)
			break
		}
		data := body[offset : offset+int(length)]
		offset += int(length)

		if flag == 0 {
			// Data frame
			foundData = true
			respMsg := &gateonv1.GetStatusResponse{}
			if err := proto.Unmarshal(data, respMsg); err != nil {
				t.Errorf("proto.Unmarshal data frame: %v", err)
			} else if respMsg.Status != "OK" {
				t.Errorf("expected status 'OK', got %q", respMsg.Status)
			}
		} else if flag == 0x80 {
			// Trailer frame
			foundTrailers = true
			trailers := string(data)
			lowerTrailers := strings.ToLower(trailers)
			if !strings.Contains(lowerTrailers, "grpc-status: 0") {
				t.Errorf("expected grpc-status: 0 in trailers, got %q", trailers)
			}
		}
	}

	if !foundData {
		t.Error("did not find data frame in response")
	}
	if !foundTrailers {
		t.Error("did not find trailer frame in response")
	}
}

func TestGRPCWebText_E2E(t *testing.T) {
	// 1. Setup Backend gRPC Server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	mockSvc := &mockApiService{}
	gateonv1.RegisterApiServiceServer(grpcServer, mockSvc)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("grpc server finished: %v", err)
		}
	}()
	defer grpcServer.Stop()

	backendAddr := "h2c://" + lis.Addr().String()

	// 2. Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: backendAddr, Weight: 1}},
	})

	// Configure Middleware
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "grpcweb-mw",
		Type: "grpcweb",
		Config: map[string]string{
			"allowed_origins": "*",
		},
	})

	// Configure Route
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:          "grpc-route",
		ServiceId:   "grpc-svc",
		Rule:        "PathPrefix(`/gateon.v1.ApiService`)",
		Type:        "grpc",
		Middlewares: []string{"grpcweb-mw"},
	})

	// 3. Prepare gRPC-Web-Text Request
	reqMsg := &gateonv1.GetStatusRequest{}
	reqData, err := proto.Marshal(reqMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	frame := make([]byte, 5+len(reqData))
	frame[0] = 0 // data frame
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(reqData)))
	copy(frame[5:], reqData)

	b64Data := base64.StdEncoding.EncodeToString(frame)

	req := httptest.NewRequest("POST", "http://localhost/gateon.v1.ApiService/GetStatus", strings.NewReader(b64Data))
	req.Header.Set("Content-Type", "application/grpc-web-text")
	req.Header.Set("X-Grpc-Web", "1")

	// 4. Handle Request
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.HandleProxyOrLocal(w, req, nil, mux)

	// 5. Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/grpc-web-text" {
		t.Errorf("expected Content-Type application/grpc-web-text, got %q", ct)
	}

	bodyB64, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	body, err := base64.StdEncoding.DecodeString(string(bodyB64))
	if err != nil {
		t.Fatalf("base64.Decode: %v. Body: %s", err, string(bodyB64))
	}

	// Parse Response Frames
	offset := 0
	foundData := false
	foundTrailers := false

	for offset < len(body) {
		if offset+5 > len(body) {
			break
		}
		flag := body[offset]
		length := binary.BigEndian.Uint32(body[offset+1 : offset+5])
		offset += 5
		if offset+int(length) > len(body) {
			break
		}
		data := body[offset : offset+int(length)]
		offset += int(length)

		if flag == 0 {
			foundData = true
			respMsg := &gateonv1.GetStatusResponse{}
			if err := proto.Unmarshal(data, respMsg); err == nil && respMsg.Status == "OK" {
				// ok
			} else {
				t.Errorf("unexpected data frame content")
			}
		} else if flag == 0x80 {
			foundTrailers = true
			if !strings.Contains(strings.ToLower(string(data)), "grpc-status: 0") {
				t.Errorf("expected grpc-status: 0 in trailers")
			}
		}
	}

	if !foundData || !foundTrailers {
		t.Errorf("missing frames: data=%v, trailers=%v", foundData, foundTrailers)
	}
}

func TestGRPCWeb_CORSPreflight(t *testing.T) {
	// Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: "h2c://127.0.0.1:1234", Weight: 1}},
	})

	// Configure Middleware
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "grpcweb-mw",
		Type: "grpcweb",
		Config: map[string]string{
			"allowed_origins": "http://localhost:3000",
		},
	})

	// Configure Route
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:          "grpc-route",
		ServiceId:   "grpc-svc",
		Rule:        "PathPrefix(`/gateon.v1.ApiService`)",
		Type:        "grpc",
		Middlewares: []string{"grpcweb-mw"},
	})

	// Prepare CORS Preflight Request
	req := httptest.NewRequest("OPTIONS", "http://localhost/gateon.v1.ApiService/GetStatus", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "x-grpc-web")

	// Handle Request
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.HandleProxyOrLocal(w, req, nil, mux)

	// Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 204 or 200, got %v. Body: %s", resp.StatusCode, w.Body.String())
	}

	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "http://localhost:3000" {
		t.Errorf("expected Access-Control-Allow-Origin: http://localhost:3000, got %q", origin)
	}

	if methods := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(methods, "POST") {
		t.Errorf("expected Access-Control-Allow-Methods to contain POST, got %q", methods)
	}
}

func TestGRPCWeb_CORS_Forbidden(t *testing.T) {
	// Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: "h2c://127.0.0.1:1234", Weight: 1}},
	})

	// Configure Middleware with STRICT allowed origins
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "grpcweb-mw",
		Type: "grpcweb",
		Config: map[string]string{
			"allowed_origins": "http://trusted.com",
		},
	})

	// Configure Route
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:          "grpc-route",
		ServiceId:   "grpc-svc",
		Rule:        "PathPrefix(`/gateon.v1.ApiService`)",
		Type:        "grpc",
		Middlewares: []string{"grpcweb-mw"},
	})

	// Prepare CORS Preflight Request from UNTRUSTED origin
	req := httptest.NewRequest("OPTIONS", "http://localhost/gateon.v1.ApiService/GetStatus", nil)
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "x-grpc-web")

	// Handle Request
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.HandleProxyOrLocal(w, req, nil, mux)

	// Verify Response
	resp := w.Result()

	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected NO Access-Control-Allow-Origin header for mismatched origin, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestGRPCWeb_BotManagement_403(t *testing.T) {
	// Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: "h2c://127.0.0.1:1234", Weight: 1}},
	})

	// Configure Bot Management Middleware
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "bot-mw",
		Type: "bot_management",
		Config: map[string]string{
			"enabled":                  "true",
			"enable_browser_integrity": "true",
		},
	})

	// Configure Route
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:          "grpc-route",
		ServiceId:   "grpc-svc",
		Rule:        "PathPrefix(`/gateon.v1.ApiService`)",
		Type:        "grpc",
		Middlewares: []string{"bot-mw", "grpcweb-mw"},
	})

	// Add grpcweb middleware
	_ = s.MwStore.Update(t.Context(), &gateonv1.Middleware{
		Id:   "grpcweb-mw",
		Type: "grpcweb",
	})

	// Prepare OPTIONS Request with Browser User-Agent but MISSING Sec-Fetch headers
	req := httptest.NewRequest("OPTIONS", "http://localhost/gateon.v1.ApiService/GetStatus", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "x-grpc-web")
	// NO Sec-Fetch headers!

	// Handle Request
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.HandleProxyOrLocal(w, req, nil, mux)

	// Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected 200/204 OK (CORS preflight bypass), got %d", resp.StatusCode)
	} else {
		t.Log("Successfully verified BotManagement bypass for CORS preflight")
	}
}

func TestGRPCWeb_HTTPS_Enforcement_403(t *testing.T) {
	// Setup Gateon Server
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

	// Configure Service
	_ = s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id:              "grpc-svc",
		WeightedTargets: []*gateonv1.Target{{Url: "h2c://127.0.0.1:1234", Weight: 1}},
	})

	// Configure Route WITH TLS but hit it via HTTP
	_ = s.RouteStore.Update(t.Context(), &gateonv1.Route{
		Id:        "grpc-route",
		ServiceId: "grpc-svc",
		Rule:      "PathPrefix(`/gateon.v1.ApiService`)",
		Type:      "grpc",
		Tls:       &gateonv1.RouteTLSConfig{OptionId: "default"}, // Enforces HTTPS
	})

	// Prepare request via HTTP (r.TLS == nil)
	req := httptest.NewRequest("POST", "http://localhost/gateon.v1.ApiService/GetStatus", nil)
	req.Header.Set("Content-Type", "application/grpc-web")

	// Handle Request
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.HandleProxyOrLocal(w, req, nil, mux)

	// Verify Response
	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden due to HTTPS enforcement, got %d", resp.StatusCode)
	} else {
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "HTTPS required" {
			t.Errorf("Expected 'HTTPS required' body, got %s", string(body))
		}
		t.Log("Successfully reproduced 403 Forbidden due to HTTPS enforcement")
	}
}
