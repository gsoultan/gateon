// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package security

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN FINDING -- needs a product decision, see the reviewer report.
//
// TestTheDashboardsDeceptionSwitchesAreTheOnesInForce: the global settings
// card offers "Inject Invisible Links" (with its own link paths and honey
// forms) under Honey-Potting & Deception. The global honeypot, which every HTTP
// entrypoint carries, reads only deception.enabled and the honeypot paths: with
// deception on it injects its own /_gateon_trap_<id> link into every HTML page
// whatever that switch says, and the global link paths and honey forms are
// injected nowhere (only the per-route deception middleware reads those keys,
// from its own config). The switch the operator sees off is not the one in
// force. Honouring it would turn breadcrumbs off for every install that
// enabled deception without touching the switch -- proto3's false -- so which
// is authoritative is the decision.
func TestTheDashboardsDeceptionSwitchesAreTheOnesInForce(t *testing.T) {
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	gc := globals.Get(t.Context())
	if gc.SecurityAdvanced == nil {
		gc.SecurityAdvanced = &gateonv1.SecurityAdvancedConfig{}
	}
	gc.SecurityAdvanced.Deception = &gateonv1.DeceptionConfig{
		Enabled:              true,
		InjectInvisibleLinks: false,
	}
	if err := globals.Update(t.Context(), gc); err != nil {
		t.Fatalf("setup: %v", err)
	}

	page := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><h1>Shop</h1></body></html>"))
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.33:40100"
	HoneypotGlobal(globals)(page).ServeHTTP(rr, req)

	if body := rr.Body.String(); strings.Contains(body, "_gateon_trap_") {
		t.Fatalf("\"Inject Invisible Links\" is off in the dashboard and the page was served with a "+
			"trap link anyway:\n%s", body)
	}
}
