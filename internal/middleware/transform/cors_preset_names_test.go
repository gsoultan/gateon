// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A preset name that is not a preset was ignored, leaving the lists empty --
// which rs/cors reads as every origin, every simple method. So "restriced",
// one letter short of the locked-down preset, produced a policy that allowed
// any origin, with nothing to say so. It is refused, and the dashboard's save
// shows why.
func TestCORSRefusesAnUnknownPreset(t *testing.T) {
	if _, err := NewCORS(map[string]string{"preset": "restriced"}); err == nil {
		t.Fatal("a cors middleware with preset \"restriced\" was built")
	}
	for _, name := range []string{"", "permissive", "standard", "grpc-web", "restricted", "Restricted", CORSPresetBackend} {
		if _, err := NewCORS(map[string]string{"preset": name}); err != nil {
			t.Errorf("preset %q was refused: %v", name, err)
		}
	}
}

// The backend preset hands a route's CORS to its backend: the middleware
// answers nothing and adds nothing.
func TestBackendCORSPresetLeavesTheRequestAlone(t *testing.T) {
	mw, err := NewCORS(map[string]string{"preset": CORSPresetBackend, "allowed_origins": "https://ignored.example"})
	if err != nil {
		t.Fatalf("NewCORS: %v", err)
	}
	reached := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !reached || rec.Code != http.StatusTeapot || len(rec.Header()) != 0 {
		t.Fatalf("the backend preset answered the preflight itself (reached=%v, %d, %v)", reached, rec.Code, rec.Header())
	}
}
