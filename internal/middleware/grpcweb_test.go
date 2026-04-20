package middleware

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGRPCWeb_PassthroughNonGRPCWeb(t *testing.T) {
	mw := GRPCWeb()
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Type", "text/html")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected handler to be called")
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
}

func TestGRPCWeb_TranslatesContentType(t *testing.T) {
	mw := GRPCWeb()

	var gotCT string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request Content-Type should be translated to application/grpc
		gotCT = r.Header.Get("Content-Type")
		// Simulate a gRPC backend response
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
		w.WriteHeader(http.StatusOK)
		// Write a gRPC data frame (flag=0x00, length=5, data="hello")
		frame := []byte{0x00, 0x00, 0x00, 0x00, 0x05}
		frame = append(frame, []byte("hello")...)
		_, _ = w.Write(frame)
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotCT != "application/grpc+proto" {
		t.Errorf("expected request Content-Type application/grpc+proto, got %q", gotCT)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/grpc-web+proto" {
		t.Errorf("expected response Content-Type application/grpc-web+proto, got %q", ct)
	}
}

func TestGRPCWeb_AppendsTrailerFrame(t *testing.T) {
	mw := GRPCWeb()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		// Write a data frame
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o'})
		// Set gRPC trailers (these appear in Header map after WriteHeader)
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "success")
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.Bytes()
	// First 8 bytes are the data frame
	if len(body) < 13 {
		t.Fatalf("expected body to contain data frame + trailer frame, got %d bytes", len(body))
	}

	// Data frame: flag(0x00) + len(3) + "foo"
	dataFrame := body[:8]
	if dataFrame[0] != 0x00 {
		t.Errorf("expected data frame flag 0x00, got 0x%02x", dataFrame[0])
	}

	// Trailer frame starts after data frame
	trailerStart := 8
	if body[trailerStart] != grpcWebTrailerFlag {
		t.Errorf("expected trailer flag 0x80, got 0x%02x", body[trailerStart])
	}

	trailerLen := binary.BigEndian.Uint32(body[trailerStart+1 : trailerStart+5])
	trailerData := string(body[trailerStart+5 : trailerStart+5+int(trailerLen)])

	if !strings.Contains(trailerData, "Grpc-Status: 0") {
		t.Errorf("expected trailer to contain Grpc-Status: 0, got %q", trailerData)
	}
	if !strings.Contains(trailerData, "Grpc-Message: success") {
		t.Errorf("expected trailer to contain Grpc-Message: success, got %q", trailerData)
	}
}

func TestGRPCWeb_TextFormatBase64(t *testing.T) {
	mw := GRPCWeb()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x02, 'h', 'i'})
		w.Header().Set("Grpc-Status", "0")
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc-web-text+proto")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); ct != "application/grpc-web-text+proto" {
		t.Errorf("expected response Content-Type application/grpc-web-text+proto, got %q", ct)
	}

	// Body should be base64-encoded
	decoded, err := base64.StdEncoding.DecodeString(rr.Body.String())
	if err != nil {
		t.Fatalf("expected base64-encoded body, decode error: %v", err)
	}

	// Should contain data frame + trailer frame
	if len(decoded) < 12 {
		t.Fatalf("expected decoded body >= 12 bytes, got %d", len(decoded))
	}

	// Data frame
	if decoded[0] != 0x00 {
		t.Errorf("expected data frame flag 0x00, got 0x%02x", decoded[0])
	}

	// Trailer frame
	trailerStart := 7 // 5 header + 2 data bytes
	if decoded[trailerStart] != grpcWebTrailerFlag {
		t.Errorf("expected trailer flag 0x80, got 0x%02x", decoded[trailerStart])
	}
}

func TestGRPCWeb_EmptyTrailers(t *testing.T) {
	mw := GRPCWeb()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 'x'})
		// No gRPC trailers set
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.Bytes()
	// Should still have a trailer frame (empty)
	trailerStart := 6 // 5 header + 1 data byte
	if trailerStart >= len(body) {
		t.Fatalf("expected trailer frame after data, body len=%d", len(body))
	}
	if body[trailerStart] != grpcWebTrailerFlag {
		t.Errorf("expected trailer flag 0x80, got 0x%02x", body[trailerStart])
	}
	trailerLen := binary.BigEndian.Uint32(body[trailerStart+1 : trailerStart+5])
	if trailerLen != 0 {
		t.Errorf("expected empty trailer frame (length 0), got %d", trailerLen)
	}
}

func TestGRPCWeb_CORS_WildcardHeaders(t *testing.T) {
	mw := GRPCWeb(CORSConfig{
		AllowedOrigins: []string{"https://cms.mulford.id"},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/poseidon.employee.EmployeeService/SignIn", nil)
	req.Header.Set("Origin", "https://cms.mulford.id")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "accept,content-type,device-id,device-name,x-grpc-web")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "https://cms.mulford.id" {
		t.Errorf("expected Access-Control-Allow-Origin https://cms.mulford.id, got %q", origin)
	}

	allowHeaders := rr.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allowHeaders, "device-id") {
		t.Errorf("expected Access-Control-Allow-Headers to contain device-id, got %q", allowHeaders)
	}
}

func TestGRPCWeb_TrailerPrefixConvention(t *testing.T) {
	mw := GRPCWeb()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 'x'})
		// Use the http.TrailerPrefix convention for trailers
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "2")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "UNKNOWN")
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.Bytes()
	trailerStart := 6 // 5 header + 1 data byte
	if trailerStart+5 > len(body) {
		t.Fatalf("body too short for trailer frame, len=%d", len(body))
	}
	if body[trailerStart] != grpcWebTrailerFlag {
		t.Errorf("expected trailer flag 0x80, got 0x%02x", body[trailerStart])
	}
	trailerLen := binary.BigEndian.Uint32(body[trailerStart+1 : trailerStart+5])
	trailerData := string(body[trailerStart+5 : trailerStart+5+int(trailerLen)])

	if !strings.Contains(trailerData, "Grpc-Status: 2") {
		t.Errorf("expected trailer to contain Grpc-Status: 2, got %q", trailerData)
	}
	if !strings.Contains(trailerData, "Grpc-Message: UNKNOWN") {
		t.Errorf("expected trailer to contain Grpc-Message: UNKNOWN, got %q", trailerData)
	}
}

func TestGRPCWeb_CORSPreflight(t *testing.T) {
	mw := GRPCWeb(CORSConfig{
		AllowedOrigins: []string{"http://example.com"},
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for preflight")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/my.Service/Method", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "X-Grpc-Web")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent && rr.Code != http.StatusOK {
		t.Errorf("expected status 204 or 200, got %d", rr.Code)
	}
	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "http://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin http://example.com, got %q", origin)
	}
	if headers := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(headers, "X-Grpc-Web") {
		t.Errorf("expected Access-Control-Allow-Headers to contain X-Grpc-Web, got %q", headers)
	}
}

func TestGRPCWeb_CORSPreflight_MissingXGrpcWeb(t *testing.T) {
	mw := GRPCWeb(CORSConfig{
		AllowedOrigins: []string{"http://example.com"},
	})

	// Next handler should be called if it's NOT a preflight or if it's a preflight that we decided to pass through.
	// But for a valid CORS preflight, c.Handler should NOT call 'next'.
	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/my.Service/Method", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	// Missing Access-Control-Request-Headers: X-Grpc-Web

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	origin := rr.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin http://example.com, got %q", origin)
	}
	if nextCalled {
		t.Error("handler should not be called for preflight")
	}
}

func TestGRPCWeb_CORSActual(t *testing.T) {
	mw := GRPCWeb(CORSConfig{
		AllowedOrigins: []string{"http://example.com"},
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/my.Service/Method", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "http://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin http://example.com, got %q", origin)
	}
	if exposed := rr.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(exposed, "Grpc-Status") {
		t.Errorf("expected Access-Control-Expose-Headers to contain Grpc-Status, got %q", exposed)
	}
}
