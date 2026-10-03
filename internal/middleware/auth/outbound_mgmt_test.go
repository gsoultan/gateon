// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/mgmtaddr"
)

// fakeManagementListener stands in for the management listener: it registers
// its port as the management port and counts the connections it accepts.
func fakeManagementListener(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	accepted = &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<title>Gateon dashboard</title>"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	prev := mgmtaddr.Register(p)
	t.Cleanup(func() { mgmtaddr.Register(prev) })
	return srv.Listener.Addr().String(), accepted
}

// A route middleware's own HTTP client must not reach the management listener
// either (ADR 0052). Forward auth and introspection dialled with the default
// transport, so an auth URL naming 127.0.0.1:<management port> reached the
// management API from loopback; forward auth even returned its response body.
func TestForwardAuthDoesNotConnectToTheManagementListener(t *testing.T) {
	addr, accepted := fakeManagementListener(t)
	mw, err := ForwardAuth(ForwardAuthConfig{Address: "http://" + addr + "/v1/status"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example/", nil))
	if n := accepted.Load(); n != 0 {
		t.Errorf("forward auth opened %d connection(s) to the management listener", n)
	}
	if rec.Code == http.StatusOK || rec.Body.String() == "<title>Gateon dashboard</title>" {
		t.Errorf("forward auth answered %d %q; want a refusal that carries nothing from the management listener",
			rec.Code, rec.Body.String())
	}
}

func TestIntrospectionDoesNotConnectToTheManagementListener(t *testing.T) {
	addr, accepted := fakeManagementListener(t)
	v, err := NewOAuth2IntrospectionValidator(OAuth2IntrospectionConfig{
		IntrospectionURL: "http://" + addr + "/v1/status", ClientID: "c", ClientSecret: "s",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
	req.Header.Set("Authorization", "Bearer app-opaque-token")
	rec := httptest.NewRecorder()
	v.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).
		ServeHTTP(rec, req)
	if n := accepted.Load(); n != 0 {
		t.Errorf("introspection opened %d connection(s) to the management listener", n)
	}
	if rec.Code == http.StatusOK {
		t.Errorf("introspection against the management listener let the request through (200)")
	}
}
