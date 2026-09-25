// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestPlainHTTPOnATCPEntrypointGetsTheEntrypointChecks: a TCP entrypoint that
// finds HTTP on a connection serves it through buildPlainHTTPHandler, whose
// chain was its own shorter copy of the HTTP entrypoint's -- without the
// global honeypot, the global GeoIP country block or the per-IP connection
// limit. Plain HTTP to a TCP entrypoint skipped all three. A request for a
// honeypot trap stands in for them here, because it needs no GeoIP database.
func TestPlainHTTPOnATCPEntrypointGetsTheEntrypointChecks(t *testing.T) {
	deps := mockDepsForInspection(t)
	reached := false
	deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	ep := &gateonv1.EntryPoint{Id: "tcp", Name: "tcp", Address: ":9000", Type: gateonv1.EntryPoint_TCP}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/_gateon_trap_probe", nil)
	req.RemoteAddr = "198.51.100.211:40000"
	rec := httptest.NewRecorder()
	buildPlainHTTPHandler(ep, deps).ServeHTTP(rec, req)

	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("a honeypot trap on a TCP entrypoint's plain HTTP: status %d, backend reached=%v; "+
			"want 403 before the backend, as on an HTTP entrypoint", rec.Code, reached)
	}
}

func globalStoreForTest(t *testing.T) config.GlobalConfigStore {
	t.Helper()
	return config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
}
