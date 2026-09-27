// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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

// The global settings card offers "Inject Invisible Links" under Honey-Potting
// & Deception. The global honeypot, which every HTTP entrypoint carries, read
// only the deception switch above it: with deception on, it injected its own
// /_gateon_trap_<id> link into every HTML page whatever "Inject Invisible Links"
// said. The switch the operator saw off was not the one in force.
//
// Root cause in one sentence: the honeypot decided on breadcrumbs from the
// deception switch, and nothing read the switch that names them.

// servedPage serves a small HTML page through the global honeypot under a
// global configuration with deception on and "Inject Invisible Links" as given.
func servedPage(t *testing.T, injectLinks bool) string {
	t.Helper()
	globals := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	gc := globals.Get(t.Context())
	if gc.SecurityAdvanced == nil {
		gc.SecurityAdvanced = &gateonv1.SecurityAdvancedConfig{}
	}
	gc.SecurityAdvanced.Deception = &gateonv1.DeceptionConfig{
		Enabled:              true,
		InjectInvisibleLinks: injectLinks,
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
	return rr.Body.String()
}

// TestTheDashboardsDeceptionSwitchesAreTheOnesInForce is the regression test.
func TestTheDashboardsDeceptionSwitchesAreTheOnesInForce(t *testing.T) {
	if body := servedPage(t, false); strings.Contains(body, "_gateon_trap_") {
		t.Fatalf("\"Inject Invisible Links\" is off in the dashboard and the page was served with a "+
			"trap link anyway:\n%s", body)
	}
}

// TestInjectInvisibleLinksStillInjects is the other half: turning the switch
// on is what puts the link in the page, so the fix is the switch being read,
// not the link being dropped.
func TestInjectInvisibleLinksStillInjects(t *testing.T) {
	if body := servedPage(t, true); !strings.Contains(body, "/_gateon_trap_") {
		t.Fatalf("\"Inject Invisible Links\" is on and the page has no trap link:\n%s", body)
	}
}

// TestTheTrapLinkAsksCrawlersNotToFollowIt: a search crawler reads markup, not
// styles, so it follows a hidden link like any other -- and following this one
// bans it. The route-level deception links carried rel="nofollow" for exactly
// that reason; the honeypot's own did not.
func TestTheTrapLinkAsksCrawlersNotToFollowIt(t *testing.T) {
	body := servedPage(t, true)
	start := strings.Index(body, "<a href=\"/_gateon_trap_")
	if start < 0 {
		t.Fatalf("setup: no trap link in the page:\n%s", body)
	}
	if link := body[start : start+strings.Index(body[start:], ">")+1]; !strings.Contains(link, `rel="nofollow"`) {
		t.Errorf("the trap link %s has no rel=\"nofollow\": a search engine that follows it is banned", link)
	}
}
