// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The management session cookie is the dashboard's bearer credential, and a
// browser does not scope cookies by port: an admin who has the dashboard open
// on host:8080 sends gateon_session with every request to every app on host.
// The proxy used to forward it, so each of those apps received an eight-hour
// admin token it could replay from anywhere (ADR 0041). These tests pin that no
// backend sees it, on every protocol the proxy speaks to a client, and that the
// cookies which do belong to the app arrive as they were sent.

const (
	// hostileCookies carries the session under both names it has had, a route's
	// own OIDC cookie whose name merely starts the same way, and two ordinary
	// cookies around them.
	hostileCookies = "other=1; gateon_session=v4.local.ADMIN; " +
		"__Host-gateon_session=v4.local.ADMIN2; gateon_session_r1=oidc; last=2"
	// survivingCookies is what the backend must see: everything but the session.
	survivingCookies = "other=1; gateon_session_r1=oidc; last=2"
)

// cookieEchoBackend answers with the Cookie header lines it received, joined
// by " | " so a header that arrived as two lines is visible as two.
func cookieEchoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Cookie", strings.Join(r.Header.Values("Cookie"), " | "))
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func credentialTestHandler(backendURL string) *ProxyHandler {
	return &ProxyHandler{
		lb:               NewRoundRobinLB([]string{backendURL}),
		stopDiscovery:    make(chan struct{}),
		stopHealthCheck:  make(chan struct{}),
		transport:        http.DefaultTransport,
		transportFactory: newBackendTransportFactory(nil, nil, nil),
	}
}

// sendThroughGateway serves h on a front of the given protocol and returns what
// the backend reported seeing.
func sendThroughGateway(t *testing.T, h http.Handler, h2 bool, cookies []string) http.Header {
	t.Helper()
	front := httptest.NewUnstartedServer(h)
	if h2 {
		front.EnableHTTP2 = true
		front.StartTLS()
	} else {
		front.Start()
	}
	t.Cleanup(front.Close)

	req, err := http.NewRequest(http.MethodGet, front.URL+"/app", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for _, c := range cookies {
		req.Header.Add("Cookie", c)
	}
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the echo backend", resp.StatusCode)
	}
	wantMajor := 1
	if h2 {
		wantMajor = 2
	}
	if resp.ProtoMajor != wantMajor {
		t.Fatalf("front spoke HTTP/%d, want HTTP/%d: the case is not testing the protocol it names", resp.ProtoMajor, wantMajor)
	}
	return resp.Header
}

func TestBackendNeverSeesTheManagementSessionCookie(t *testing.T) {
	backend := cookieEchoBackend(t)
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"HTTP/1.1", false}, {"HTTP/2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := credentialTestHandler(backend.URL)
			defer h.Close()
			seen := sendThroughGateway(t, h, tc.h2, []string{hostileCookies})
			if got := seen.Get("X-Seen-Cookie"); got != survivingCookies {
				t.Errorf("backend saw Cookie %q, want %q: the admin's session cookie was forwarded to a proxied app",
					got, survivingCookies)
			}
		})
	}
}

// TestSessionCookieIsStrippedFromEveryCookieLine covers a client that sends
// more than one Cookie line, which HTTP/1.1 clients do and HTTP/2 permits.
// Checking only the first line would leave the session in the second; a line
// that held nothing but the session is dropped rather than sent empty.
func TestSessionCookieIsStrippedFromEveryCookieLine(t *testing.T) {
	backend := cookieEchoBackend(t)
	h := credentialTestHandler(backend.URL)
	defer h.Close()

	seen := sendThroughGateway(t, h, false, []string{"a=1", "gateon_session=v4.local.ADMIN", "b=2;__Host-gateon_session=x"})
	if got, want := seen.Get("X-Seen-Cookie"), "a=1 | b=2"; got != want {
		t.Errorf("backend saw Cookie lines %q, want %q", got, want)
	}
}

// TestCookiesWithoutTheSessionPassUntouched is the other half: a request with
// no session cookie must reach the backend byte for byte, spacing included.
func TestCookiesWithoutTheSessionPassUntouched(t *testing.T) {
	backend := cookieEchoBackend(t)
	h := credentialTestHandler(backend.URL)
	defer h.Close()

	const odd = "a=1;b=2;  gateon_session_r1=x ;gateon_sessionx=y"
	seen := sendThroughGateway(t, h, false, []string{odd})
	if got := seen.Get("X-Seen-Cookie"); got != odd {
		t.Errorf("backend saw Cookie %q, want it untouched as %q", got, odd)
	}
}

// TestGRPCBackendNeverSeesTheManagementSessionCookie sends a gRPC-shaped
// request over HTTP/2 to an h2c backend: the path a gRPC client takes, which
// the proxy rewrites differently from plain HTTP.
func TestGRPCBackendNeverSeesTheManagementSessionCookie(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Cookie", strings.Join(r.Header.Values("Cookie"), " | "))
		w.Header().Set("X-Seen-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
	}))
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	backend.Config.Protocols = protocols
	backend.Start()
	t.Cleanup(backend.Close)

	h := credentialTestHandler(strings.Replace(backend.URL, "http://", "h2c://", 1))
	defer h.Close()
	front := httptest.NewUnstartedServer(h)
	front.EnableHTTP2 = true
	front.StartTLS()
	t.Cleanup(front.Close)

	req, err := http.NewRequest(http.MethodPost, front.URL+"/pkg.Svc/Method", strings.NewReader("\x00\x00\x00\x00\x00"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Cookie", hostileCookies)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("gRPC request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if p := resp.Header.Get("X-Seen-Proto"); p != "HTTP/2.0" {
		t.Fatalf("backend was reached over %q, want HTTP/2.0: the case is not the gRPC path", p)
	}
	if got := resp.Header.Get("X-Seen-Cookie"); got != survivingCookies {
		t.Errorf("gRPC backend saw Cookie %q, want %q", got, survivingCookies)
	}
}

// apiTokenShaped has the shape of a gateway API token: the prefix and 43
// base64url characters.
const apiTokenShaped = "gateon_tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// sessionsAccepting accepts one token as a management session and refuses the
// rest, counting what it was asked.
type sessionsAccepting struct {
	token string
	asked *int
}

func (s sessionsAccepting) VerifyToken(token string) (any, error) {
	*s.asked++
	if token == s.token {
		return struct{}{}, nil
	}
	return nil, errors.New("not a session")
}

// TestBackendNeverSeesAManagementBearerToken covers the other way a session
// travels: as a bearer token, which a script holding one might send to an app
// on the same gateway. Only a token the management plane accepts is withheld;
// an app's own PASETO token, or any other credential, passes as sent, and a
// credential that is not PASETO is never handed to the verifier.
func TestBackendNeverSeesAManagementBearerToken(t *testing.T) {
	backend := cookieEchoBackend(t)
	asked := 0
	h := credentialTestHandler(backend.URL)
	h.sessions = sessionsAccepting{token: "v4.local.MGMT", asked: &asked}
	defer h.Close()
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	for _, tc := range []struct {
		name, header, want string
		asks               int
	}{
		{"management session", "Bearer v4.local.MGMT", "", 1},
		{"management session, scheme in another case", "bearer v4.local.MGMT", "", 1},
		{"an app's own PASETO token", "Bearer v4.local.APP", "Bearer v4.local.APP", 1},
		{"a JWT", "Bearer eyJhbGciOi.x.y", "Bearer eyJhbGciOi.x.y", 0},
		{"basic credentials", "Basic YWxpY2U6cHc=", "Basic YWxpY2U6cHc=", 0},
		// ADR 0050: a gateway API token is withheld by its shape, with no lookup.
		{"a gateway API token", "Bearer " + apiTokenShaped, "", 0},
		{"something merely prefixed like one", "Bearer gateon_tok_short", "Bearer gateon_tok_short", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked = 0
			req, err := http.NewRequest(http.MethodGet, front.URL+"/app", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", tc.header)
			resp, err := front.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()
			if got := resp.Header.Get("X-Seen-Authorization"); got != tc.want {
				t.Errorf("backend saw Authorization %q, want %q", got, tc.want)
			}
			if asked != tc.asks {
				t.Errorf("verifier asked %d times, want %d", asked, tc.asks)
			}
		})
	}
}

// TestStripAllocatesNothingWithoutASession pins the cost the request path
// pays on every request that carries no management credential.
func TestStripAllocatesNothingWithoutASession(t *testing.T) {
	h := &ProxyHandler{sessions: sessionsAccepting{token: "v4.local.MGMT", asked: new(int)}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "a=1; theme=dark; gateon_session_r1=oidc; _ga=GA1.2.3")
	r.Header.Set("Authorization", "Bearer eyJhbGciOi.x.y")
	if n := testing.AllocsPerRun(100, func() { h.withholdManagementCredentials(r) }); n != 0 {
		t.Errorf("withholding credentials from a request with none allocated %.0f times per request, want 0", n)
	}
}

func TestWebSocketBackendNeverSeesTheManagementSessionCookie(t *testing.T) {
	backend, seen := upgradeBackend(t)
	gw := upgradeGateway(t, backend.URL)

	extra := http.Header{}
	extra.Set("Cookie", hostileCookies)
	dialUpgrade(t, gw.URL, extra)

	var got http.Header
	select {
	case got = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the upgrade request")
	}
	if c := got.Get("Cookie"); c != survivingCookies {
		t.Errorf("WebSocket backend saw Cookie %q, want %q: the admin's session cookie rode the upgrade",
			c, survivingCookies)
	}
}
