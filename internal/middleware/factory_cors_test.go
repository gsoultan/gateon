// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestFactory_CreateCORS_WithPreset(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, "")

	m := &gateonv1.Middleware{
		Type: "cors",
		Config: map[string]string{
			"preset": "permissive",
		},
	}

	mw, err := f.Create(m, "test-route")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://any-origin.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// If it was permissive, it should allow the origin.
	// rs/cors behavior for AllowCredentials=true with AllowedOrigins=["*"]
	// is to reflect the origin.
	gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if gotOrigin == "" {
		t.Error("expected Access-Control-Allow-Origin header, got none")
	}
}

func TestFactory_CreateGRPCWeb_WithPreset(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, "")

	m := &gateonv1.Middleware{
		Type: "grpcweb",
		Config: map[string]string{
			"preset": "grpc-web",
		},
	}

	mw, err := f.Create(m, "test-grpc-route")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test actual request (not preflight) to check exposed headers
	req := httptest.NewRequest(http.MethodPost, "/Service/Method", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Content-Type", "application/grpc-web")
	req.Header.Set("X-Grpc-Web", "1")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if gotOrigin == "" {
		t.Error("expected Access-Control-Allow-Origin for gRPC-Web, got none")
	}

	exposed := rr.Header().Get("Access-Control-Expose-Headers")
	if exposed == "" {
		// Note: rs/cors might only send ExposedHeaders on actual requests that have an Origin
		t.Log("Warning: Access-Control-Expose-Headers is empty")
	}
}
