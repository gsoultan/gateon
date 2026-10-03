// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The management API authenticates a browser by its cookie, and a browser
// attaches that cookie to a request whichever page asked for it. SameSite=Lax
// narrowed "whichever" to the same site -- which, for a dashboard on an IP
// address, is every port on it, the apps this gateway proxies included. One
// text/plain POST from such a page set a credentialed management CORS origin
// that survived a restart (review M5, ADR 0041). These pin the refusal, and
// that the dashboard and a script are still let through.

// forgedCORSWrite is the review's payload: a body that, accepted, grants the
// attacker's origin credentialed cross-origin access to the whole API.
const forgedCORSWrite = `{"management":{"cors":{"allowedOrigins":["https://evil.example"],"allowCredentials":true}}}`

// mgmtWrite sends one POST to the management handler with the given headers
// and the admin's session cookie.
func mgmtWrite(h http.Handler, path, body string, hdr map[string]string, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://gateway.example:8080"+path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:5555"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestCrossOriginWritesWithTheSessionCookieAreRefused(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")

	for _, tc := range []struct {
		name string
		hdr  map[string]string
	}{
		{"cross-site text/plain", map[string]string{
			"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", "Content-Type": "text/plain;charset=UTF-8"}},
		{"same-site text/plain from another port", map[string]string{
			"Sec-Fetch-Site": "same-site", "Origin": "http://gateway.example", "Content-Type": "text/plain;charset=UTF-8"}},
		{"cross-site JSON", map[string]string{
			"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", "Content-Type": "application/json"}},
		{"same-site JSON from a sibling subdomain", map[string]string{
			"Sec-Fetch-Site": "same-site", "Origin": "https://app.gateway.example", "Content-Type": "application/json"}},
		{"older browser, foreign Origin, no Sec-Fetch-Site", map[string]string{
			"Origin": "https://evil.example", "Content-Type": "application/json"}},
		{"opaque origin", map[string]string{
			"Origin": "null", "Content-Type": "application/json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := mgmtWrite(h, "/v1/global", forgedCORSWrite, tc.hdr, cookie)
			if rr.Code != http.StatusForbidden {
				t.Errorf("forged POST /v1/global = %d, want 403: a page on another origin changed the "+
					"gateway's configuration with the admin's cookie; body: %s", rr.Code, rr.Body.String())
			}
		})
	}

	// None of them may have landed.
	rr := serveMgmt(h, http.MethodGet, "/v1/global", "", cookie)
	if strings.Contains(rr.Body.String(), "evil.example") {
		t.Errorf("a forged write persisted a management CORS origin: %s", rr.Body.String())
	}
}

// TestCrossOriginLoginAndSetupAreRefused: signing a victim's browser in to
// the attacker's account (login CSRF) is a write too.
func TestCrossOriginLoginAndSetupAreRefused(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	hdr := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", "Content-Type": "application/json"}
	for _, path := range []string{"/v1/login", "/v1/setup", "/gateon.v1.ApiService/Login"} {
		rr := mgmtWrite(h, path, `{"username":"root","password":"correct-horse"}`, hdr, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s = %d, want 403; body: %s", path, rr.Code, rr.Body.String())
		}
	}
}

// TestNonJSONWritesAreRefused covers a browser that sends neither
// Sec-Fetch-Site nor Origin on a form post: the body type is the second line.
// text/plain, form-urlencoded and multipart are the types a page can send
// cross-origin without a preflight.
func TestNonJSONWritesAreRefused(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")
	for _, ct := range []string{"text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		rr := mgmtWrite(h, "/v1/global", forgedCORSWrite, map[string]string{"Content-Type": ct}, cookie)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("POST /v1/global as %s = %d, want 415; body: %s", ct, rr.Code, rr.Body.String())
		}
	}
	rr := mgmtWrite(h, "/v1/global", forgedCORSWrite, nil, cookie)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("POST /v1/global with a body and no Content-Type = %d, want 415", rr.Code)
	}
}

// TestDashboardAndScriptWritesStillWork is the other half: the dashboard's own
// same-origin write, an older browser's same-origin write that carries only
// Origin, and a script that sends a bearer token and neither header.
func TestDashboardAndScriptWritesStillWork(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")
	const benign = `{"management":{"allowedHosts":["gateway.example"]}}`

	for _, tc := range []struct {
		name   string
		hdr    map[string]string
		cookie string
	}{
		{"dashboard", map[string]string{
			"Sec-Fetch-Site": "same-origin", "Origin": "http://gateway.example:8080", "Content-Type": "application/json"}, cookie},
		{"older browser, same origin", map[string]string{
			"Origin": "http://gateway.example:8080", "Content-Type": "application/json; charset=utf-8"}, cookie},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rr := mgmtWrite(h, "/v1/global", benign, tc.hdr, tc.cookie); rr.Code != http.StatusOK {
				t.Errorf("POST /v1/global = %d, want 200; body: %s", rr.Code, rr.Body.String())
			}
		})
	}

	t.Run("script with a bearer token", func(t *testing.T) {
		token, _, err := mgr.Authenticate("root", "correct-horse", "")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		hdr := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
		if rr := mgmtWrite(h, "/v1/global", benign, hdr, ""); rr.Code != http.StatusOK {
			t.Errorf("script POST /v1/global = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bodiless write from the dashboard", func(t *testing.T) {
		hdr := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://gateway.example:8080"}
		if rr := mgmtWrite(h, "/v1/logout", "", hdr, cookie); rr.Code != http.StatusOK {
			t.Errorf("POST /v1/logout without a body = %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestAConfiguredCORSOriginMayWrite: an operator who serves the dashboard from
// another origin names it in management CORS, and that is what lets it write.
func TestAConfiguredCORSOriginMayWrite(t *testing.T) {
	h, _, _, _ := buildManagementStack(t, []string{"https://dash.example"})
	cookie := signInCookie(t, h, "root", "correct-horse")
	hdr := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://dash.example", "Content-Type": "application/json"}
	if rr := mgmtWrite(h, "/v1/global", `{"management":{"allowedHosts":["x"]}}`, hdr, cookie); rr.Code != http.StatusOK {
		t.Errorf("POST from the configured origin = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	hdr["Origin"] = "https://evil.example"
	if rr := mgmtWrite(h, "/v1/global", `{}`, hdr, cookie); rr.Code != http.StatusForbidden {
		t.Errorf("POST from an unconfigured origin = %d, want 403", rr.Code)
	}
}

// TestQueryTokenIsIgnoredOnAnEventStreamGet: a token in the URL authenticated
// any GET that sent Accept: text/event-stream (review M15).
func TestQueryTokenIsIgnoredOnAnEventStreamGet(t *testing.T) {
	h, mgr, _ := buildManagementHandler(t)
	token, _, err := mgr.Authenticate("root", "correct-horse", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example:8080/v1/global?token="+token, nil)
	req.Header.Set("Accept", "text/event-stream")
	req.RemoteAddr = "203.0.113.9:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/global?token=… with an SSE Accept header = %d, want 401; body: %.200s", rr.Code, rr.Body.String())
	}
}

// TestLogsHandshakeThroughTheManagementPlane opens /v1/logs the way the
// dashboard does, through the whole management handler, with the cookie.
func TestLogsHandshakeThroughTheManagementPlane(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/logs"

	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"https://evil.example", http.StatusForbidden},
		{srv.URL, http.StatusSwitchingProtocols},
	} {
		hdr := http.Header{"Origin": {tc.origin}, "Cookie": {sessionCookie + "=" + cookie}}
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
		if conn != nil {
			_ = conn.Close()
		}
		if resp == nil {
			t.Fatalf("handshake from %s got no response: %v", tc.origin, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("/v1/logs handshake from %s = %d, want %d", tc.origin, resp.StatusCode, tc.want)
		}
	}
}

// TestProxiedBackendNeverSeesTheManagementCredential is the wiring test for
// ADR 0041's proxy half: a route served by the real server, with the real auth
// manager, withholds the admin's cookie and bearer token from its backend.
func TestProxiedBackendNeverSeesTheManagementCredential(t *testing.T) {
	seen := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
	}))
	t.Cleanup(backend.Close)

	route := &gateonv1.Route{Id: "app", ServiceId: "app", Type: "http", Rule: "Host(`app.example.com`)"}
	_, s, mgr, _ := buildManagementStack(t, nil, route)
	if err := s.ServiceStore.Update(t.Context(), &gateonv1.Service{
		Id: "app", Name: "app", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	token, _, err := mgr.Authenticate("root", "correct-horse", "")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/page", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "theme=dark; "+sessionCookie+"="+token+"; cart=7")
	rr := httptest.NewRecorder()
	// The route's compiled chain, as HandleProxyOrLocal serves a data-plane
	// request: built by the server's proxy cache, which is where the auth
	// manager is handed to the proxy.
	s.GetOrCreateProxy(route).ServeHTTP(rr, req)

	var got http.Header
	select {
	case got = <-seen:
	default:
		t.Fatalf("the backend was never reached (status %d: %s)", rr.Code, rr.Body.String())
	}
	if c := got.Get("Cookie"); c != "theme=dark; cart=7" {
		t.Errorf("backend saw Cookie %q, want %q: the admin's session reached a proxied app", c, "theme=dark; cart=7")
	}
	if a := got.Get("Authorization"); a != "" {
		t.Errorf("backend saw Authorization %q: the admin's bearer token reached a proxied app", a)
	}
}

// TestManagementCORSDefaultsToNoCrossOriginAccess: with nothing configured, a
// foreign origin is told nothing. It used to be told "*".
func TestManagementCORSDefaultsToNoCrossOriginAccess(t *testing.T) {
	t.Setenv("GATEON_CORS_ORIGINS", "")
	h, _, _ := buildManagementHandler(t) // wires BuildManagementCORS(nil), as Run does with no config
	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		req := httptest.NewRequest(method, "http://gateway.example:8080/v1/setup/required", nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		req.RemoteAddr = "203.0.113.9:5555"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if v := rr.Header().Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s with no CORS configured sent Access-Control-Allow-Origin %q to a foreign origin, want none",
				method, v)
		}
	}
}

// TestManagementResponsesAreNotStored: an API answer holds configuration,
// users and secrets' placeholders; no cache on the way, the browser's included,
// may keep it.
func TestManagementResponsesAreNotStored(t *testing.T) {
	h, _, _ := buildManagementHandler(t)
	cookie := signInCookie(t, h, "root", "correct-horse")
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/global", ""},
		{http.MethodPost, "/gateon.v1.ApiService/GetStatus", "{}"},
	} {
		req := httptest.NewRequest(tc.method, "http://gateway.example:8080"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.9:5555"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s = %d, want 200; body: %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
		if v := rr.Header().Get("Cache-Control"); v != "no-store" {
			t.Errorf("%s %s Cache-Control = %q, want no-store", tc.method, tc.path, v)
		}
	}

	// A PUT answer is never cacheable, and Chromium keeps no inspector copy of
	// one marked no-store, which left the Playwright specs that read the
	// dashboard's PUT /v1/global answer waiting until they timed out.
	rr := mgmtWrite(h, "/v1/global", `{"management":{"allowedHosts":["x"]}}`,
		map[string]string{"Content-Type": "application/json"}, cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /v1/global = %d: %s", rr.Code, rr.Body.String())
	}
	req := httptest.NewRequest(http.MethodPut, "http://gateway.example:8080/v1/global", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5555"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	put := httptest.NewRecorder()
	h.ServeHTTP(put, req)
	if v := put.Header().Get("Cache-Control"); v != "" {
		t.Errorf("PUT /v1/global Cache-Control = %q, want none: a PUT answer is not cacheable", v)
	}
}
