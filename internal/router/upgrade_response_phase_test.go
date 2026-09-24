// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An Upgrade header is a request, not a fact. The client writes it, and a
// backend that does not speak the named protocol ignores it and answers the
// request normally. That answer is an ordinary response and has to reach the
// client through the same response-phase controls as any other -- here the
// global WAF's data-leak inspection, which refuses a card number on its way
// out.
//
// The proxy took the client's socket away from net/http as soon as it saw any
// Upgrade header, before it knew whether the backend would switch protocols,
// and wrote whatever the backend answered straight onto that socket. Every
// ResponseWriter the middleware chain had wrapped was bypassed, so adding
// "Upgrade: x" to a request was enough to read the response the WAF would
// have blocked.
func TestUpgradeHeaderDoesNotBypassResponseInspection(t *testing.T) {
	const card = "4111111111111111" // Luhn-valid test Visa, which the DLP rules detect
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// An ordinary application endpoint: it ignores Upgrade entirely.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"account":"alice","card":"`+card+`"}`)
	}))
	defer backend.Close()

	gw := newDLPGateway(t, backend.URL)

	// Control: an ordinary request for the same resource is refused its leak.
	// Without this the assertion below could pass because DLP never ran.
	if resp := rawGET(t, gw, ""); strings.Contains(resp, card) {
		t.Fatalf("control: the WAF's data-leak inspection let the card number through on a plain "+
			"request, so this test would prove nothing:\n%s", resp)
	}

	// The same request, naming a protocol the backend does not speak.
	if resp := rawGET(t, gw, "Upgrade: anything\r\n"); strings.Contains(resp, card) {
		t.Fatalf("adding an Upgrade header the backend ignored returned the card number the WAF "+
			"refuses on the same request without it; the response bypassed response inspection:\n%s", resp)
	}
}

// newDLPGateway serves one route to backendURL with the global WAF's
// data-leak inspection on.
func newDLPGateway(t *testing.T, backendURL string) string {
	t.Helper()
	rt := &gateonv1.Route{Id: "r-dlp", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http"}
	gStore := fakeGlobalStore{cfg: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, Dlp: true, ParanoiaLevel: 2},
	}}
	return newRouteGateway(t, backendURL, rt, fakeMWStore{}, gStore)
}

// newRouteGateway serves rt, whose service "svc" points at backendURL, through
// ApplyRouteMiddlewares and the real ProxyHandler, behind the entrypoint
// middleware, on a real listener so the proxy can hijack a connection. It
// returns the listener's address.
func newRouteGateway(t *testing.T, backendURL string, rt *gateonv1.Route, mwStore fakeMWStore, gStore fakeGlobalStore) string {
	t.Helper()
	services := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: backendURL, Weight: 1}},
	}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	ph := proxy.NewProxyHandler(rt, services)
	t.Cleanup(ph.Close)

	chain := ApplyRouteMiddlewares(ph, rt, nil, mwStore, gStore, nil, nil)
	srv := httptest.NewServer(middleware.EntryPoint("web", "web", false)(chain))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// rawGET sends one GET over a fresh TCP connection, with extra header lines
// written verbatim, and returns the whole response as read by the client.
func rawGET(t *testing.T, addr, extraHeaders string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := "GET /account HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: curl/8.0\r\n" +
		"Accept: application/json\r\n" + extraHeaders + "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.Status + "\n" + string(body)
}
