// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/server/handlers"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MGMT-N1, ADR 0051. ADR 0041 withheld the dashboard's credentials from the
// backend, in the proxy -- after the route's middlewares. A forwardauth
// middleware copies every request header to its auth URL and OAuth2
// introspection POSTs the request's token, so an operator who could create
// and bind either one, pointed at a server of their own, collected the
// administrator's session from the administrator's own browser. These tests
// drive the gateway the way production assembles it: a data-plane entrypoint,
// the base handler, the route's middleware chain and the proxy.

const (
	// credAppToken is the opaque token an app's introspection endpoint accepts.
	credAppToken = "app-opaque-token"
	// credJWTSecret and credPasetoKey are an app's own keys, not the gateway's.
	credJWTSecret = "app-jwt-secret-app-jwt-secret-00"
	credPasetoKey = "app-paseto-key-app-paseto-key-00"
)

// recorder keeps every Cookie line and Authorization value a server was sent,
// and every token= an introspection endpoint was asked about.
type recorder struct {
	mu     sync.Mutex
	cookie []string
	authz  []string
	tokens []string
}

func (r *recorder) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookie = append(r.cookie, req.Header.Values("Cookie")...)
	r.authz = append(r.authz, req.Header.Values("Authorization")...)
	if req.Method == http.MethodPost && req.ParseForm() == nil {
		if tok := req.PostForm.Get("token"); tok != "" {
			r.tokens = append(r.tokens, tok)
		}
	}
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cookie, r.authz, r.tokens = nil, nil, nil
}

// seen is everything recorded, one string, for a containment check.
func (r *recorder) seen() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.cookie, " | ") + " || " + strings.Join(r.authz, " | ") + " || " + strings.Join(r.tokens, " | ")
}

func (r *recorder) cookies() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.cookie, " | ")
}

func (r *recorder) introspected() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

// credFixture is a gateway with one administrator signed in, an operator's
// forwardauth and introspection servers, and the backends behind them.
type credFixture struct {
	t        *testing.T
	s        *Server
	mgmt     http.Handler // the management listener
	data     http.Handler // a data-plane entrypoint
	session  string       // the administrator's session token
	scrape   string       // an administrator-issued metrics:read token
	authSrv  *recorder    // what the forwardauth server was sent
	intro    *recorder    // what the introspection endpoint was sent
	backend  *recorder    // what the HTTP backends were sent
	grpcSeen *recorder    // what the gRPC backend was sent
}

func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	f := &credFixture{t: t, authSrv: &recorder{}, intro: &recorder{}, backend: &recorder{}, grpcSeen: &recorder{}}
	f.s, f.mgmt, f.data = buildCredGateway(t)
	c := mgmtClient{t: t, h: f.mgmt}
	f.session = sessionFor(t, c, "root", "correct-horse")
	_, f.scrape = issueScrapeToken(t, c, f.session)
	f.seed(f.startServers())
	return f
}

// credServers are the outside world the fixture's routes point at.
type credServers struct{ auth, intro, http, ws, grpc string }

func (f *credFixture) startServers() credServers {
	t := f.t
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.authSrv.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authSrv.Close)
	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.intro.record(r)
		w.Header().Set("Content-Type", "application/json")
		active := r.PostForm.Get("token") == credAppToken
		_, _ = io.WriteString(w, `{"active":`+map[bool]string{true: "true", false: "false"}[active]+`,"sub":"app-user"}`)
	}))
	t.Cleanup(intro.Close)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.backend.record(r)
		_, _ = io.WriteString(w, "app")
	}))
	t.Cleanup(backend.Close)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.backend.record(r)
		if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(ws.Close)
	return credServers{auth: authSrv.URL, intro: intro.URL, http: backend.URL, ws: ws.URL, grpc: f.startGRPCBackend()}
}

// startGRPCBackend is an h2c server that answers like a gRPC service, which is
// what a gRPC-typed route's target is.
func (f *credFixture) startGRPCBackend() string {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.grpcSeen.record(r)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Seen-Proto", r.Proto)
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Grpc-Status", "0")
	}))
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	f.t.Cleanup(srv.Close)
	return strings.Replace(srv.URL, "http://", "h2c://", 1)
}

func (f *credFixture) seed(srv credServers) {
	t, ctx := f.t, f.t.Context()
	mws := []*gateonv1.Middleware{
		{Id: "fa", Name: "fa", Type: "forwardauth", Config: map[string]string{"address": srv.auth + "/verify"}},
		{Id: "intro", Name: "intro", Type: "auth", Config: map[string]string{
			"type": "oauth2", "introspection_url": srv.intro, "client_id": "gw", "client_secret": "s3cret"}},
		{Id: "jwt", Name: "jwt", Type: "auth", Config: map[string]string{"type": "jwt", "secret": credJWTSecret}},
		{Id: "paseto", Name: "paseto", Type: "auth", Config: map[string]string{"type": "paseto", "secret": credPasetoKey}},
	}
	svcs := []*gateonv1.Service{
		{Id: "http", WeightedTargets: []*gateonv1.Target{{Url: srv.http, Weight: 1}}},
		{Id: "ws", WeightedTargets: []*gateonv1.Target{{Url: srv.ws, Weight: 1}}},
		{Id: "grpc", WeightedTargets: []*gateonv1.Target{{Url: srv.grpc, Weight: 1}}},
	}
	routes := []*gateonv1.Route{
		{Id: "fa", ServiceId: "http", Type: "http", Rule: "PathPrefix(`/app`)", Middlewares: []string{"fa"}},
		{Id: "fa-ws", ServiceId: "ws", Type: "http", Rule: "PathPrefix(`/ws`)", Middlewares: []string{"fa"}},
		{Id: "fa-grpc", ServiceId: "grpc", Type: "grpc", Rule: "PathPrefix(`/pkg.Svc`)", Middlewares: []string{"fa"}},
		{Id: "intro", ServiceId: "http", Type: "http", Rule: "PathPrefix(`/introspected`)", Middlewares: []string{"intro"}},
		{Id: "jwt", ServiceId: "http", Type: "http", Rule: "PathPrefix(`/jwt`)", Middlewares: []string{"jwt"}},
		{Id: "paseto", ServiceId: "http", Type: "http", Rule: "PathPrefix(`/paseto`)", Middlewares: []string{"paseto"}},
	}
	for _, m := range mws {
		if err := f.s.MwStore.Update(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range svcs {
		if err := f.s.ServiceStore.Update(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, rt := range routes {
		if err := f.s.RouteStore.Update(ctx, rt); err != nil {
			t.Fatal(err)
		}
	}
}

// buildCredGateway assembles the management listener and a data-plane
// entrypoint ("web") around one base handler, as Run and StartServers do.
func buildCredGateway(t testing.TB) (*Server, http.Handler, http.Handler) {
	t.Helper()
	tmp := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), "0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "root", Password: "correct-horse", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(tmp, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(tmp, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(tmp, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(tmp, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(tmp, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(tmp, "global.json"))),
		WithAuthManager(mgr),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GlobalStore.Update(t.Context(), &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
	}); err != nil {
		t.Fatal(err)
	}
	apiSvc := api.NewApiService(api.ApiServiceConfig{
		Routes: s.RouteStore, Services: s.ServiceStore, Globals: s.GlobalStore,
		EntryPoints: s.EpStore, Middlewares: s.MwStore, TLSOptions: s.TLSOptStore, Auth: s.AuthManager,
	})
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(NewGRPCRBACInterceptor()))
	gateonv1.RegisterApiServiceServer(grpcServer, apiSvc)
	internalAPI := transform.NewDefaultGRPCWebDetector(grpcServer)
	mux := http.NewServeMux()
	mux.Handle(apiConnectHandler(apiSvc))
	deps := handlerDeps(s)
	deps.MgmtOrigins = BuildManagementOrigins(&gateonv1.ManagementConfig{})
	handlers.RegisterRESTHandlers(mux, apiSvc, deps)
	base := CreateBaseHandler(http.NotFoundHandler(), BaseHandlerDeps{
		ProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.HandleProxyOrLocal(w, r, grpcServer, internalAPI, mux)
		}),
		RouteStore: s.RouteStore, GlobalReg: s.GlobalStore, Auth: s.AuthManager, MgmtOrigins: deps.MgmtOrigins,
	}, internalAPI, mux)
	return s, middleware.EntryPoint("management", "management", true)(base), middleware.EntryPoint("web", "web", false)(base)
}

// adminBrowserCookies is what an administrator's browser sends every app on
// the dashboard's host: the session under both names it has had, a route's own
// OIDC cookie whose name merely starts the same way, and the app's cookies.
func adminBrowserCookies(session string) string {
	return "other=1; gateon_session=" + session + "; __Host-gateon_session=" + session + "; gateon_session_r1=oidc; last=2"
}

// appCookies is what must survive: every cookie but the session.
const appCookies = "other=1; gateon_session_r1=oidc; last=2"

// credentialCase is one way a management credential reaches an app.
type credentialCase struct {
	name    string
	header  func(f *credFixture) http.Header
	secret  func(f *credFixture) string
	cookies string // what the app must still receive
}

func credentialCases() []credentialCase {
	return []credentialCase{
		{"session cookie", func(f *credFixture) http.Header {
			return http.Header{"Cookie": {adminBrowserCookies(f.session)}}
		}, func(f *credFixture) string { return f.session }, appCookies},
		{"session bearer", func(f *credFixture) http.Header {
			return http.Header{"Authorization": {"Bearer " + f.session}, "Cookie": {"other=1"}}
		}, func(f *credFixture) string { return f.session }, "other=1"},
		{"scrape token", func(f *credFixture) http.Header {
			return http.Header{"Authorization": {"Bearer " + f.scrape}, "Cookie": {"other=1"}}
		}, func(f *credFixture) string { return f.scrape }, "other=1"},
	}
}

// frontend serves the data-plane entrypoint over HTTP/1.1, or TLS with h2.
func (f *credFixture) frontend(h2 bool) *httptest.Server {
	srv := httptest.NewUnstartedServer(f.data)
	if h2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	f.t.Cleanup(srv.Close)
	return srv
}

// answer is what the client got back; the body has been read and closed.
type answer struct {
	StatusCode, ProtoMajor int
	Header                 http.Header
}

func (f *credFixture) send(t *testing.T, front *httptest.Server, method, path string, body io.Reader, hdr http.Header) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, front.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return answer{StatusCode: resp.StatusCode, ProtoMajor: resp.ProtoMajor, Header: resp.Header}
}

func (f *credFixture) resetSeen() {
	f.authSrv.reset()
	f.intro.reset()
	f.backend.reset()
	f.grpcSeen.reset()
}

// assertNeverSeen fails if any outside server was sent secret, and checks the
// app's own cookies reached the auth server intact.
func (f *credFixture) assertNeverSeen(t *testing.T, secret, wantCookies string) {
	t.Helper()
	for name, r := range map[string]*recorder{
		"forwardauth server": f.authSrv, "introspection endpoint": f.intro, "backend": f.backend, "gRPC backend": f.grpcSeen,
	} {
		if strings.Contains(r.seen(), secret) {
			t.Errorf("the %s was sent the management credential: %.300s", name, r.seen())
		}
	}
	if wantCookies == "" {
		return
	}
	if got := f.authSrv.cookies(); got != wantCookies {
		t.Errorf("the forwardauth server saw Cookie %q, want the app's cookies intact as %q", got, wantCookies)
	}
	if got := f.backend.cookies() + f.grpcSeen.cookies(); got != wantCookies {
		t.Errorf("the backend saw Cookie %q, want the app's cookies intact as %q", got, wantCookies)
	}
}

// TestForwardAuthNeverSeesAManagementCredential: on every protocol a route
// speaks -- HTTP/1.1, HTTP/2, a WebSocket upgrade and gRPC -- neither the
// forwardauth server nor the backend behind it receives the administrator's
// session cookie (either name), the session as a bearer, or a scrape token;
// and the app's own cookies arrive at both as they were sent.
func TestForwardAuthNeverSeesAManagementCredential(t *testing.T) {
	f := newCredFixture(t)
	h1, h2 := f.frontend(false), f.frontend(true)
	for _, tc := range credentialCases() {
		t.Run(tc.name+"/HTTP1.1", func(t *testing.T) {
			f.resetSeen()
			if resp := f.send(t, h1, http.MethodGet, "/app", nil, tc.header(f)); resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}
			f.assertNeverSeen(t, tc.secret(f), tc.cookies)
		})
		t.Run(tc.name+"/HTTP2", func(t *testing.T) {
			f.resetSeen()
			resp := f.send(t, h2, http.MethodGet, "/app", nil, tc.header(f))
			if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
				t.Fatalf("status %d over HTTP/%d, want 200 over HTTP/2", resp.StatusCode, resp.ProtoMajor)
			}
			f.assertNeverSeen(t, tc.secret(f), tc.cookies)
		})
		t.Run(tc.name+"/gRPC", func(t *testing.T) {
			f.resetSeen()
			hdr := tc.header(f)
			hdr.Set("Content-Type", "application/grpc")
			resp := f.send(t, h2, http.MethodPost, "/pkg.Svc/Method", strings.NewReader("\x00\x00\x00\x00\x00"), hdr)
			if resp.Header.Get("X-Seen-Proto") != "HTTP/2.0" {
				t.Fatalf("status %d, gRPC backend reached over %q: the case is not the gRPC path",
					resp.StatusCode, resp.Header.Get("X-Seen-Proto"))
			}
			f.assertNeverSeen(t, tc.secret(f), tc.cookies)
		})
		t.Run(tc.name+"/WebSocket", func(t *testing.T) {
			f.resetSeen()
			f.dialWebSocket(t, h1, tc.header(f))
			f.assertNeverSeen(t, tc.secret(f), tc.cookies)
		})
	}
}

func (f *credFixture) dialWebSocket(t *testing.T, front *httptest.Server, hdr http.Header) {
	t.Helper()
	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme, u.Path = "ws", "/ws"
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	conn, resp, err := dialer.DialContext(t.Context(), u.String(), hdr)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("WebSocket through the gateway: %v (status %d)", err, status)
	}
	_ = conn.Close()
}

// TestIntrospectionNeverPostsAManagementCredential: the administrator's
// browser carries the session cookie and the app's own token. The app's
// introspection endpoint is asked about the app's token -- the request is let
// through -- and never about the session; with no app token, or with only a
// management credential, nothing is posted at all.
func TestIntrospectionNeverPostsAManagementCredential(t *testing.T) {
	f := newCredFixture(t)
	front := f.frontend(false)

	browser := http.Header{"Cookie": {adminBrowserCookies(f.session)}, "Authorization": {"Bearer " + credAppToken}}
	if resp := f.send(t, front, http.MethodGet, "/introspected", nil, browser); resp.StatusCode != http.StatusOK {
		t.Errorf("admin browser with the app's token: %d, want 200", resp.StatusCode)
	}
	if got := f.intro.introspected(); len(got) != 1 || got[0] != credAppToken {
		t.Errorf("introspection was asked about %q, want only the app's token", got)
	}
	f.assertNeverSeen(t, f.session, "")

	for _, tc := range credentialCases() {
		t.Run(tc.name, func(t *testing.T) {
			f.resetSeen()
			if resp := f.send(t, front, http.MethodGet, "/introspected", nil, tc.header(f)); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("only a management credential: %d, want 401", resp.StatusCode)
			}
			if got := f.intro.introspected(); len(got) != 0 {
				t.Errorf("introspection was posted %q, want nothing", got)
			}
			f.assertNeverSeen(t, tc.secret(f), "")
		})
	}
}

// TestAppAuthAcceptsTheAdminBrowsersAppToken: the session cookie used to take
// precedence over the app's own bearer token in every route-level JWT and
// PASETO check, so a route behind one refused the administrator's browser
// whatever app token it presented.
func TestAppAuthAcceptsTheAdminBrowsersAppToken(t *testing.T) {
	f := newCredFixture(t)
	front := f.frontend(false)
	for _, tc := range []struct{ path, token string }{
		{"/jwt", mintAppJWT(t)},
		{"/paseto", mintAppPaseto(t)},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f.resetSeen()
			hdr := http.Header{"Cookie": {adminBrowserCookies(f.session)}, "Authorization": {"Bearer " + tc.token}}
			if resp := f.send(t, front, http.MethodGet, tc.path, nil, hdr); resp.StatusCode != http.StatusOK {
				t.Errorf("admin browser with the app's token: %d, want 200", resp.StatusCode)
			}
			f.assertNeverSeen(t, f.session, "")
			if got := f.backend.cookies(); got != appCookies {
				t.Errorf("backend saw Cookie %q, want %q", got, appCookies)
			}
		})
	}
}

func mintAppJWT(t *testing.T) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "app-user", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(credJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mintAppPaseto(t *testing.T) string {
	t.Helper()
	key, err := paseto.V4SymmetricKeyFromBytes([]byte(credPasetoKey))
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetString("sub", "app-user")
	tok.SetExpiration(time.Now().Add(time.Hour))
	return tok.V4Encrypt(key, nil)
}

// TestTheManagementPlaneStillAuthenticatesWithItsCredentials is the other
// half: withholding is for the data plane. The management listener, and the
// management API on a data-plane entrypoint that is allowed to serve it, still
// accept the session cookie; and a path that only looks like the management
// API before its dot segments are resolved is a route's, and withheld.
func TestTheManagementPlaneStillAuthenticatesWithItsCredentials(t *testing.T) {
	f := newCredFixture(t)
	cookie := http.Header{"Cookie": {adminBrowserCookies(f.session)}}

	mgmt := httptest.NewServer(f.mgmt)
	t.Cleanup(mgmt.Close)
	if resp := f.send(t, mgmt, http.MethodGet, "/v1/status", nil, cookie); resp.StatusCode != http.StatusOK {
		t.Errorf("management listener with the session cookie: %d, want 200", resp.StatusCode)
	}

	gc := f.s.GlobalStore.Get(context.Background())
	gc.Management = &gateonv1.ManagementConfig{AllowPublicManagement: true}
	if err := f.s.GlobalStore.Update(t.Context(), gc); err != nil {
		t.Fatal(err)
	}
	front := f.frontend(false)
	if resp := f.send(t, front, http.MethodGet, "/v1/status", nil, cookie); resp.StatusCode != http.StatusOK {
		t.Errorf("public management API with the session cookie: %d, want 200", resp.StatusCode)
	}

	// A path that is the management API's only until its dot segments are
	// resolved is the app route's. The JWT route reads the session cookie
	// ahead of the app's token, so it lets the browser in only if the session
	// was withheld before it.
	for _, path := range []string{"/v1/status/../../jwt", "/v1/status/%2e%2e/%2e%2e/jwt"} {
		f.resetSeen()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.URL.Opaque = path // sent as written, not cleaned by the client
		req.Header.Set("Cookie", adminBrowserCookies(f.session))
		req.Header.Set("Authorization", "Bearer "+mintAppJWT(t))
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s with the admin cookie and the app's token: %d, want 200 from the app route", path, resp.StatusCode)
		}
		f.assertNeverSeen(t, f.session, "")
		if got := f.backend.cookies(); got != appCookies {
			t.Errorf("%s: backend saw Cookie %q, want %q", path, got, appCookies)
		}
	}
}

// TestRouteMiddlewaresRefuseAManagementCredentialThatReachesThem is the second
// line: a request handed to the route chain beneath the base handler -- which
// production never does, and which is exactly the case this line exists for --
// still sends no management credential to the forwardauth server or the
// introspection endpoint. The session bearer case needs the management plane's
// verifier to have been handed to the route's middlewares by the proxy cache.
func TestRouteMiddlewaresRefuseAManagementCredentialThatReachesThem(t *testing.T) {
	f := newCredFixture(t)
	below := middleware.EntryPoint("web", "web", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.s.HandleProxyOrLocal(w, r, nil, nil, http.NewServeMux())
	}))
	front := httptest.NewServer(below)
	t.Cleanup(front.Close)
	for _, tc := range credentialCases() {
		t.Run(tc.name, func(t *testing.T) {
			f.resetSeen()
			if resp := f.send(t, front, http.MethodGet, "/app", nil, tc.header(f)); resp.StatusCode != http.StatusOK {
				t.Fatalf("forwardauth route: %d, want 200", resp.StatusCode)
			}
			f.assertNeverSeen(t, tc.secret(f), tc.cookies)

			f.resetSeen()
			hdr := tc.header(f)
			if tc.name == "session cookie" {
				hdr.Set("Authorization", "Bearer "+credAppToken)
			}
			resp := f.send(t, front, http.MethodGet, "/introspected", nil, hdr)
			f.assertNeverSeen(t, tc.secret(f), "")
			if tc.name == "session cookie" && resp.StatusCode != http.StatusOK {
				t.Errorf("introspection route, admin browser with the app's token: %d, want 200", resp.StatusCode)
			}
		})
	}
}
