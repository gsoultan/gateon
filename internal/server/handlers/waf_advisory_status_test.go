// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security/waf/advisory"
)

func advisoryStatusAs(t *testing.T, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/waf/advisory", nil)
	if claims != nil {
		req = req.WithContext(context.WithValue(t.Context(), middleware.UserContextKey, claims))
	}
	rec := httptest.NewRecorder()
	serveWAFAdvisoryStatus(rec, req)
	return rec
}

// The status says whether there is a worker and what became of the samples.
// It is counts and a host: a viewer may read it, nobody unauthenticated may,
// and the token is not in it.
func TestWAFAdvisoryStatusSaysWhatTheSwitchDoesOnThisGateway(t *testing.T) {
	viewer := &auth.Claims{ID: "2", Username: "viewer", Role: auth.RoleViewer}
	shared := advisory.Shared
	t.Cleanup(func() { advisory.Shared = shared })

	advisory.Shared = advisory.Off
	if rec := advisoryStatusAs(t, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no caller read the status: %d", rec.Code)
	}
	var off advisory.Status
	rec := advisoryStatusAs(t, viewer)
	if err := json.Unmarshal(rec.Body.Bytes(), &off); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if off.Configured {
		t.Errorf("a gateway with no worker says it has one: %+v", off)
	}

	q, err := advisory.New(advisory.Config{
		URL: "https://worker.example:8443/", Token: "the-gateway-token", Mode: advisory.Reputation, Capacity: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	advisory.Shared = func() *advisory.Queue { return q }
	for range 3 {
		r := httptest.NewRequest(http.MethodGet, "/a", nil)
		if s, ok := advisory.Capture(r, "route", advisory.WhySampled, nil); ok {
			q.Offer(s)
		}
	}
	rec = advisoryStatusAs(t, viewer)
	var on advisory.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &on); err != nil {
		t.Fatal(err)
	}
	if !on.Configured || on.Worker != "https://worker.example:8443" || on.Mode != advisory.Reputation ||
		on.Offered != 3 || on.Dropped != 2 || on.Queued != 1 || on.QueueCapacity != 1 {
		t.Errorf("status %+v", on)
	}
	if strings.Contains(rec.Body.String(), "the-gateway-token") {
		t.Errorf("the status carries the token: %s", rec.Body)
	}
}
