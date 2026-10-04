// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/mgmtaddr"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// countingListener counts the connections its server accepts.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// managementStandIn is a backend registered as this gateway's management
// listener, as the management listener registers itself when it binds. It
// answers "dashboard" over HTTP/1, h2c and (when tls) HTTP/2, and counts the
// connections that reach it.
func managementStandIn(t *testing.T, tls bool) (*httptest.Server, *countingListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "dashboard")
	}))
	cl := &countingListener{Listener: srv.Listener}
	srv.Listener = cl
	if tls {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Config.Protocols = new(http.Protocols)
		srv.Config.Protocols.SetHTTP1(true)
		srv.Config.Protocols.SetUnencryptedHTTP2(true)
		srv.Start()
	}
	t.Cleanup(srv.Close)
	unregister := mgmtaddr.RegisterListener(srv.Listener.Addr())
	t.Cleanup(unregister)
	return srv, cl
}

func standInPort(srv *httptest.Server) string {
	return strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
}

// TestTheProxyDoesNotConnectToTheManagementListener (ADR 0052, review finding
// MGMT-N2): a service whose target reaches the gateway's own management
// listener -- here by the name localhost, as a target saved under a name that
// later resolves to this host would -- is answered with a gateway error on
// every HTTP transport, and no connection reaches the listener. Before, the
// proxy connected from loopback and served the dashboard.
func TestTheProxyDoesNotConnectToTheManagementListener(t *testing.T) {
	for _, tc := range []struct {
		name, scheme string
		tls, pp      bool
	}{
		{"HTTP/1", "http", false, false},
		{"PROXY protocol", "http", false, true},
		{"h2c", "h2c", false, false},
		{"HTTPS", "https", true, false},
		{"HTTP/2 over TLS", "h2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cl := managementStandIn(t, tc.tls)
			target := tc.scheme + "://localhost:" + standInPort(srv)
			reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
			if err := reg.Update(context.Background(), &gateonv1.Service{Id: "loop", Name: "loop",
				WeightedTargets: []*gateonv1.Target{{Url: target, Weight: 1, ProxyProtocolEnabled: tc.pp}},
				TlsClientConfig: &gateonv1.TlsClientConfig{Enabled: true, SkipVerify: true}}); err != nil {
				t.Fatal(err)
			}
			ph := NewProxyHandler(&gateonv1.Route{Id: "loop-route", ServiceId: "loop"}, reg)
			defer ph.Close()
			rec := httptest.NewRecorder()
			ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))
			if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
				t.Errorf("a request to %s answered %d %q; want 502 or 503", target, rec.Code, rec.Body.String())
			}
			if n := cl.accepted.Load(); n != 0 {
				t.Errorf("%d connection(s) reached the management listener through %s", n, target)
			}
		})
	}
}

// TestAWebSocketUpgradeDoesNotConnectToTheManagementListener: the upgrade
// path dials for itself, and is refused as the transports are.
func TestAWebSocketUpgradeDoesNotConnectToTheManagementListener(t *testing.T) {
	srv, cl := managementStandIn(t, false)
	gw := upgradeGateway(t, "http://localhost:"+standInPort(srv))
	conn, err := net.Dial("tcp", gw.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: public.example\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade answer: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.StatusCode < 500 {
		t.Errorf("an upgrade to the management listener answered %d; want a gateway error", resp.StatusCode)
	}
	if n := cl.accepted.Load(); n != 0 {
		t.Errorf("%d upgrade connection(s) reached the management listener", n)
	}
}

// TestHTTP2OverTLSStillReachesABackend: the h2 transport now dials through
// backendDialer and checks the negotiated protocol itself, as http2.Transport
// did when it dialled; an ordinary HTTP/2 backend is still served.
func TestHTTP2OverTLSStillReachesABackend(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{Id: "h2", Name: "h2",
		WeightedTargets: []*gateonv1.Target{{Url: "h2://localhost:" + standInPort(srv), Weight: 1}},
		TlsClientConfig: &gateonv1.TlsClientConfig{Enabled: true, SkipVerify: true}}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "h2-route", ServiceId: "h2"}, reg)
	defer ph.Close()
	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "HTTP/2.0" {
		t.Fatalf("an h2 backend answered %d %q through the proxy; want 200 over HTTP/2.0", rec.Code, rec.Body.String())
	}
}
