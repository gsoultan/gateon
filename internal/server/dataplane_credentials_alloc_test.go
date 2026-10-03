// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestDataPlaneEntryAllocatesNothingWithoutAManagementCredential pins what
// ADR 0051 costs nearly every request: one scan of its Cookie and
// Authorization values: no allocation, and no global-configuration read.
func TestDataPlaneEntryAllocatesNothingWithoutAManagementCredential(t *testing.T) {
	asked := 0
	reads := &countingGlobals{GlobalConfigStore: config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))}
	deps := BaseHandlerDeps{GlobalReg: reads}
	entry := withholdFromDataPlane(deps, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked++ }))
	req := httptest.NewRequest(http.MethodGet, "http://gateway.test/v1/status", nil)
	req.Header.Set("Cookie", "a=1; theme=dark; gateon_session_r1=oidc; _ga=GA1.2.3")
	req.Header.Set("Authorization", "Bearer eyJhbGciOi.x.y")
	w := httptest.NewRecorder()
	if n := testing.AllocsPerRun(200, func() { entry.ServeHTTP(w, req) }); n != 0 {
		t.Errorf("the data-plane entry allocated %.0f times per request without a management credential, want 0", n)
	}
	if reads.n != 0 {
		t.Errorf("the global configuration was read %d times for requests with no management credential, want 0", reads.n)
	}
	if asked == 0 {
		t.Fatal("the next handler was never reached")
	}
}

// countingGlobals counts reads of the global configuration.
type countingGlobals struct {
	config.GlobalConfigStore
	n int
}

func (c *countingGlobals) Get(ctx context.Context) *gateonv1.GlobalConfig {
	c.n++
	return c.GlobalConfigStore.Get(ctx)
}
