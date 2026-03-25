package entrypoint

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// mockDeps provides minimal deps for inspection integration test.
func mockDepsForInspection(t *testing.T) *Deps {
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("inspected-http"))
	})
	noopCORS := &mockCORS{}
	noopLimiter := middleware.NoopRateLimiter{}
	tlsMgr := gtls.NewManager(gtls.Config{})
	return &Deps{
		BaseHandler:      baseHandler,
		Wrapped:          &mockGRPCWeb{},
		CORS:             noopCORS,
		TLSConfig:        nil,
		TLSManager:       tlsMgr,
		Limiter:          noopLimiter,
		ShutdownRegistry: &ShutdownRegistry{},
		L4Resolver:       nil,
	}
}

type mockCORS struct{}

func (m *mockCORS) Handler(h http.Handler) http.Handler { return h }

type mockGRPCWeb struct{}

func (m *mockGRPCWeb) IsGrpcWebRequest(r *http.Request) bool            { return false }
func (m *mockGRPCWeb) IsAcceptableGrpcCorsRequest(r *http.Request) bool { return false }
func (m *mockGRPCWeb) IsGrpcWebSocketRequest(r *http.Request) bool      { return false }
func (m *mockGRPCWeb) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

// TestIntegration_TCPInspection verifies connection-time inspection routes
// HTTP traffic to HTTP handler and non-HTTP to L4.
func TestIntegration_TCPInspection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ep := &gateonv1.EntryPoint{
		Id:               "test-ep",
		Address:          addr,
		Type:             gateonv1.EntryPoint_TCP,
		Protocols:        []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
		ReadTimeoutMs:    15000,
		WriteTimeoutMs:   15000,
		AccessLogEnabled: false,
	}
	deps := mockDepsForInspection(t)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTCPConnWithInspection(conn, ep, deps, nil)
		}
	}()

	t.Run("HTTP_request_routed_to_HTTP_handler", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()

		req := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
		_, err = conn.Write([]byte(req))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		_ = conn.(*net.TCPConn).CloseWrite()

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		if !bytes.Contains(body, []byte("inspected-http")) {
			t.Errorf("expected body to contain 'inspected-http', got %q", body)
		}
	})

	t.Run("raw_bytes_routed_to_L4", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte{0x00, 0x01, 0x02, 0x03})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		_ = conn.(*net.TCPConn).CloseWrite()

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil && err != io.EOF {
			t.Fatalf("Read: %v", err)
		}
		if !strings.Contains(string(got), "Gateon TCP Entrypoint") {
			t.Errorf("expected L4 response with 'Gateon TCP Entrypoint', got %q", got)
		}
	})

	_ = ln.Close()
	wg.Wait()
}

func TestIntegration_TCPInspection_RedisNotRoutedToHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ep := &gateonv1.EntryPoint{
		Id:               "test-ep",
		Address:          addr,
		Type:             gateonv1.EntryPoint_TCP,
		Protocols:        []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
		ReadTimeoutMs:    15000,
		WriteTimeoutMs:   15000,
		AccessLogEnabled: false,
	}
	deps := mockDepsForInspection(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTCPConnWithInspection(conn, ep, deps, nil)
		}
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Redis PING: *1\r\n$4\r\nPING\r\n
	redisPing := []byte("*1\r\n$4\r\nPING\r\n")
	_, _ = conn.Write(redisPing)
	_ = conn.(*net.TCPConn).CloseWrite()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(conn)
	if bytes.Contains(got, []byte("inspected-http")) {
		t.Errorf("Redis-like traffic should NOT be routed to HTTP, got %q", got)
	}
	if !strings.Contains(string(got), "Gateon TCP Entrypoint") {
		t.Errorf("expected L4 response, got %q", got)
	}
}
