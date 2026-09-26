// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func serveThroughEntrypoint(t *testing.T, backend http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	deps := &Deps{GlobalStore: config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))}
	ep := &gateonv1.EntryPoint{Id: "web", Name: "web", Address: ":8080"}
	h := middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(backend)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
	return rec
}

// TestProxiedPagesKeepTheirOwnSecurityPolicy: the entrypoint applied the
// dashboard's "recommended" headers to every response it served, so a proxied
// page that sent no CSP got the gateway's -- script-src 'self' with a nonce no
// backend can know, fonts and images from its own origin only, form-action
// 'self', frame-ancestors 'none' -- and HSTS with includeSubDomains. Inline
// scripts, CDN assets, web fonts, a login form posting to an identity
// provider and embedding in an iframe all broke behind the gateway.
func TestProxiedPagesKeepTheirOwnSecurityPolicy(t *testing.T) {
	rec := serveThroughEntrypoint(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script>boot()</script><script src="https://cdn.example/app.js"></script>`))
	})
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "Permissions-Policy"} {
		if v := rec.Header().Get(k); v != "" {
			t.Errorf("a proxied page that set no %s got the gateway's: %q", k, v)
		}
	}

	// A backend's own policy goes out exactly as it sent it.
	const own = "default-src https:"
	rec = serveThroughEntrypoint(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", own)
		_, _ = w.Write([]byte("ok"))
	})
	if got := rec.Header().Values("Content-Security-Policy"); len(got) != 1 || got[0] != own {
		t.Errorf("backend's CSP arrived as %q, want exactly %q", got, own)
	}
}
