// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An entrypoint with access logging on logged every request, and the route
// the request reached logged it again: two lines per request, doubling the
// log volume -- and the disk writes on a small host -- for every routed
// request. And both recorded the TCP peer, which behind a load balancer is
// the load balancer on every line.
func TestARoutedRequestIsLoggedOnceWithItsClient(t *testing.T) {
	buf := captureAccessLogs(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	dir := t.TempDir()
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: upstream.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("service: %v", err)
	}
	rt := &gateonv1.Route{Id: "logged", Name: "logged-route", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http"}
	ph := proxy.NewProxyHandler(rt, services)
	defer ph.Close()
	global := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	routeChain := router.ApplyRouteMiddlewares(ph, rt, nil,
		config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")), global, nil, nil)

	ep := &gateonv1.EntryPoint{Id: "web", Name: "web", Address: ":8080", AccessLogEnabled: true}
	deps := &Deps{GlobalStore: global}
	routed := middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(routeChain)
	unrouted := middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(http.NotFoundHandler())

	serveFrom(routed, "198.51.100.23:5000")
	lines := accessLines(buf)
	if len(lines) != 1 {
		t.Fatalf("one routed request produced %d access log lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if !strings.Contains(lines[0], "route=logged-route") || !strings.Contains(lines[0], "client=198.51.100.23") {
		t.Fatalf("the access log line does not name the route and the client:\n%s", lines[0])
	}

	// A request no route took is still logged, once, by the entrypoint.
	buf.Reset()
	serveFrom(unrouted, "198.51.100.23:5000")
	if lines := accessLines(buf); len(lines) != 1 || !strings.Contains(lines[0], "route=gateon-web") {
		t.Fatalf("a request no route took produced %q", lines)
	}
}

func serveFrom(h http.Handler, remoteAddr string) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/page", nil)
	req.RemoteAddr = remoteAddr
	h.ServeHTTP(httptest.NewRecorder(), req)
}

func accessLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, `msg="access log"`) {
			out = append(out, line)
		}
	}
	return out
}

// captureAccessLogs points logger.L at a shim with no logger of its own, so it
// falls through to slog's default, which this swaps for a buffer.
func captureAccessLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevShim, prevDefault := logger.L, slog.Default()
	logger.L = &logger.SlogShim{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		logger.L = prevShim
		slog.SetDefault(prevDefault)
	})
	return &buf
}
