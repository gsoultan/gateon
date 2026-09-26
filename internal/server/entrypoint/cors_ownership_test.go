// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	appOrigin  = "https://app.example.com"
	evilOrigin = "https://attacker.example.com"
)

// The entrypoint answered every CORS preflight itself, first in its chain and
// with a permissive, credential-free policy, before a route was chosen. A
// route's own cors middleware therefore never saw a preflight: one that
// allows credentials for its origins could not be used for any request that
// needs a preflight (a JSON POST, a PUT, an Authorization header), because the
// browser requires Access-Control-Allow-Credentials on the preflight too. And
// the origins it refused were allowed anyway.
func TestARoutesCORSPolicyAnswersItsOwnPreflights(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), &gateonv1.Middleware{Id: "cors", Type: "cors", Config: map[string]string{
		"allowed_origins": appOrigin, "allow_credentials": "true",
		"allowed_methods": "GET,POST,PUT", "allowed_headers": "Content-Type",
	}})

	resp := preflight(t, gw, appOrigin)
	if resp.StatusCode/100 != 2 || resp.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		resp.Header.Get("Access-Control-Allow-Origin") != appOrigin {
		t.Fatalf("a preflight from %s, which the route's policy allows with credentials, got %s with "+
			"Access-Control-Allow-Origin %q and Access-Control-Allow-Credentials %q; the browser refuses "+
			"a credentialed request without both", appOrigin, resp.Status,
			resp.Header.Get("Access-Control-Allow-Origin"), resp.Header.Get("Access-Control-Allow-Credentials"))
	}

	if got := preflight(t, gw, evilOrigin).Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("a preflight from %s, which the route's policy does not allow, was granted %q",
			evilOrigin, got)
	}
}

// A route with no cors middleware leaves CORS to its backend -- which is where
// most applications implement it. The entrypoint answered the backend's
// preflights for it, without credentials, and set Access-Control-Allow-Origin
// on every response before proxying; the backend's own header was then added
// as a second value, and browsers refuse a response with two. A backend that
// handles CORS itself could not be used cross-origin behind the gateway at all.
func TestABackendsOwnCORSPolicyReachesTheBrowser(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == appOrigin {
			w.Header().Set("Access-Control-Allow-Origin", appOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "PUT")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "backend")
			return
		}
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")
		_, _ = io.WriteString(w, "ok")
	}))

	resp := preflight(t, gw, appOrigin)
	if resp.Body != "backend" || resp.Header.Get("Access-Control-Allow-Credentials") != "true" ||
		resp.Header.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("the backend answers its own preflights, with credentials and a max age of 600, but the "+
			"browser got %s %q with Access-Control-Allow-Credentials %q and Access-Control-Max-Age %q",
			resp.Status, resp.Body, resp.Header.Get("Access-Control-Allow-Credentials"),
			resp.Header.Get("Access-Control-Max-Age"))
	}

	resp = get(t, gw, appOrigin)
	if got := resp.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != appOrigin {
		t.Fatalf("the backend's response arrived with Access-Control-Allow-Origin %q; browsers refuse "+
			"anything but exactly one value", got)
	}
	if got := resp.Header.Values("Access-Control-Expose-Headers"); len(got) != 1 || got[0] != "X-Total-Count" {
		t.Fatalf("the backend exposes X-Total-Count and the browser was told %q", got)
	}
}

// A route with its own CORS policy strips the backend's CORS headers, so the
// browser reads one policy. The strip named Access-Control-Exposed-Headers,
// which is no header -- the real one is Access-Control-Expose-Headers -- so
// the backend's list went out beside the route's, and a script on an allowed
// origin could read every response header the backend chose to expose.
func TestARouteCORSPolicyReplacesTheBackendsExposedHeaders(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Expose-Headers", "X-Backend-Secret")
		_, _ = io.WriteString(w, "ok")
	}), &gateonv1.Middleware{Id: "cors", Type: "cors", Config: map[string]string{
		"allowed_origins": appOrigin, "exposed_headers": "X-Route-Exposed",
	}})

	got := strings.Join(get(t, gw, appOrigin).Header.Values("Access-Control-Expose-Headers"), ", ")
	if strings.Contains(got, "X-Backend-Secret") || !strings.Contains(got, "X-Route-Exposed") {
		t.Fatalf("the route's policy exposes X-Route-Exposed, and the browser was told %q", got)
	}
}

// A backend that enforces its own origin allowlist refuses an origin by
// leaving Access-Control-Allow-Origin off -- and a route with no cors
// middleware reads that silence as "no CORS here" and supplies the permissive
// default, granting the refused origin. The backend preset says the route's
// CORS is the backend's: nothing is added, nothing answered, nothing stripped.
func TestARouteCanLeaveCORSEntirelyToItsBackend(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == appOrigin {
			w.Header().Set("Access-Control-Allow-Origin", appOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "PUT")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}), &gateonv1.Middleware{Id: "cors", Type: "cors", Config: map[string]string{"preset": "backend"}})

	for _, r := range []reply{preflight(t, gw, evilOrigin), get(t, gw, evilOrigin)} {
		if got := r.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("the backend refused %s by omission, but the gateway granted it %q", evilOrigin, got)
		}
	}
	resp := get(t, gw, appOrigin)
	if got := resp.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != appOrigin ||
		resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("the backend's own grant reached the browser as Allow-Origin %q, Allow-Credentials %q",
			got, resp.Header.Get("Access-Control-Allow-Credentials"))
	}
}

// A backend that does not handle CORS still gets the gateway's permissive,
// credential-free default, on its preflights and on its responses, so moving
// the default off the entrypoint does not break the cross-origin callers that
// depended on it. Both halves passed before this change and must still pass.
func TestABackendWithoutCORSGetsThePermissiveDefault(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))

	resp := preflight(t, gw, evilOrigin)
	if resp.StatusCode/100 != 2 || resp.Header.Get("Access-Control-Allow-Origin") != evilOrigin ||
		!strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), http.MethodPut) {
		t.Fatalf("a preflight to a backend without CORS got %s, Allow-Origin %q, Allow-Methods %q; the "+
			"permissive default should have answered it", resp.Status,
			resp.Header.Get("Access-Control-Allow-Origin"), resp.Header.Get("Access-Control-Allow-Methods"))
	}
	if resp.Body != "" {
		t.Fatalf("the default preflight answer carried the backend's body %q", resp.Body)
	}
	// The backend's body is dropped here rather than written into the 204,
	// where net/http refuses it; the proxy aborts on that refusal and the
	// server closes the connection, so every such preflight cost one.
	preflight(t, gw, evilOrigin)
	if n := gw.opened.Load(); n != 1 {
		t.Fatalf("two preflights on one keep-alive client opened %d connections to the gateway", n)
	}

	resp = get(t, gw, evilOrigin)
	if got := resp.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != evilOrigin {
		t.Fatalf("a response from a backend without CORS got Access-Control-Allow-Origin %q", got)
	}
	for _, r := range []reply{preflight(t, gw, evilOrigin), get(t, gw, evilOrigin)} {
		if r.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("the permissive default allowed credentials to an arbitrary origin")
		}
	}
}

// A refusal made on the route is still readable by the page that caused it,
// so a single-page app can tell "blocked" and "slow down" from a network
// failure.
func TestARouteRefusalIsReadableCrossOrigin(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), &gateonv1.Middleware{Id: "deny", Type: "ipfilter", Config: map[string]string{
		"deny_list": "127.0.0.1",
	}})

	resp := get(t, gw, appOrigin)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Access-Control-Allow-Origin") != appOrigin {
		t.Fatalf("a route refusal came back %s with Access-Control-Allow-Origin %q", resp.Status,
			resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

// Browsers send Origin on every WebSocket handshake, so the default policy sits
// in the path of every browser WebSocket on a route without a cors middleware,
// and the proxy needs the client connection to tunnel it.
func TestABrowserWebSocketStillUpgrades(t *testing.T) {
	gw := corsGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\ntunnelled")
		_ = rw.Flush()
	}))

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gw.url, "http://"), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: app.example.com\r\nOrigin: "+appOrigin+
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("a browser WebSocket handshake got %s", resp.Status)
	}
	if got, _ := io.ReadAll(br); string(got) != "tunnelled" {
		t.Fatalf("the tunnel carried %q", got)
	}
}

// corsGateway serves one route to backend through the HTTP entrypoint's chain,
// the route's middleware chain and the real proxy, the way compile assembles
// them.
type corsGW struct {
	url    string
	opened atomic.Int32
}

func corsGateway(t *testing.T, backend http.Handler, mws ...*gateonv1.Middleware) *corsGW {
	t.Helper()
	upstream := httptest.NewServer(backend)
	t.Cleanup(upstream.Close)

	ctx := context.Background()
	dir := t.TempDir()
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := services.Update(ctx, &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: upstream.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	mwStore := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	rt := &gateonv1.Route{Id: "r", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http"}
	for _, mw := range mws {
		if err := mwStore.Update(ctx, mw); err != nil {
			t.Fatalf("update middleware: %v", err)
		}
		rt.Middlewares = append(rt.Middlewares, mw.Id)
	}

	stripCORS := router.RouteReplacesBackendCORS(ctx, rt, mwStore)
	ph := proxy.NewProxyHandlerBuilder(rt, services, nil).SetStripCORS(stripCORS).Build()
	t.Cleanup(ph.Close)
	global := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	routeChain := router.ApplyRouteMiddlewares(ph, rt, nil, mwStore, global, nil, nil)

	ep := &gateonv1.EntryPoint{Id: "web", Name: "web", Address: ":8080"}
	front := middleware.Chain(entrypointChain(t.Context(), ep, &Deps{GlobalStore: global})...)(routeChain)
	gw := &corsGW{}
	srv := httptest.NewUnstartedServer(front)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			gw.opened.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	gw.url = srv.URL
	return gw
}

func preflight(t *testing.T, gw *corsGW, origin string) reply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodOptions, gw.url+"/api/items", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	return do(t, req)
}

func get(t *testing.T, gw *corsGW, origin string) reply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, gw.url+"/api/items", nil)
	req.Header.Set("Origin", origin)
	return do(t, req)
}

// reply is a response read to the end, so the connection goes back to the
// client's pool before the next request.
type reply struct {
	Status     string
	StatusCode int
	Header     http.Header
	Body       string
}

func do(t *testing.T, req *http.Request) reply {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", req.Method, req.URL, err)
	}
	return reply{Status: resp.Status, StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}
}
