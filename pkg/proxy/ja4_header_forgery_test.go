// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const forgedJA4 = "forged-fingerprint"

// TestUpgradeDoesNotForwardAClientsJA4Header sends a websocket upgrade that
// carries its own X-Gateon-JA4. The upgrade path copied the client's headers
// verbatim and never touched this one, so a backend that trusts the header
// read whatever the client claimed.
func TestUpgradeDoesNotForwardAClientsJA4Header(t *testing.T) {
	backend, seen := upgradeBackend(t)
	gw := upgradeGateway(t, backend.URL)
	dialUpgrade(t, gw.URL, http.Header{"X-Gateon-Ja4": {forgedJA4}})
	if got := (<-seen).Get("X-Gateon-JA4"); got == forgedJA4 {
		t.Fatal("the backend received the client's own X-Gateon-JA4 on an upgrade")
	}
}

// TestProxyDoesNotForwardAClientsJA4Header guards the HTTP path, where the
// gateway computes an HTTP fingerprint for every request and overwrites the
// header with it. It does not reproduce a defect -- the deletion setGatewayJA4
// adds there is defensive, for a request the gateway has no fingerprint for --
// but it keeps the two paths from drifting apart again.
func TestProxyDoesNotForwardAClientsJA4Header(t *testing.T) {
	got := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Gateon-JA4")
	}))
	defer backend.Close()
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "ja4", Name: "ja4", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "ja4-route", ServiceId: "ja4"}, reg)
	defer ph.Close()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("X-Gateon-JA4", forgedJA4)
	ph.ServeHTTP(httptest.NewRecorder(), req)
	if <-got == forgedJA4 {
		t.Fatal("the backend received the client's own X-Gateon-JA4")
	}
}
