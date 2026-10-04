// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// hangUpBackend accepts each request and closes the connection without an
// answer: a transport error on every request, as a crashed backend gives.
func hangUpBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server cannot hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestProxyErrorLinesAreRateLimited: the proxy wrote one ERROR line per failed
// request, so a backend failing under load made the gateway write one per
// request, past journald's budget, which then dropped every other line from
// the service. 200 failed requests write at most two seconds' worth (twenty),
// and the report accounts for every line left out, by route and target.
func TestProxyErrorLinesAreRateLimited(t *testing.T) {
	const failures = 200
	var buf bytes.Buffer
	prevShim, prevDefault, prevLines := logger.L, slog.Default(), proxyErrorLines
	logger.L = &logger.SlogShim{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	proxyErrorLines = logger.NewLineLimiter(logger.LineLimit{
		Level: slog.LevelError, Summary: "proxy errors left out", PerSecond: proxyErrorLinesPerSecond,
		Every: proxyErrorReportEvery, Labels: [2]string{"route", "target"},
	})
	backend := hangUpBackend(t)
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "hangup", Name: "hangup", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "hangup-route", ServiceId: "hangup"}, reg)
	t.Cleanup(func() {
		ph.Close()
		logger.L = prevShim
		slog.SetDefault(prevDefault)
		proxyErrorLines = prevLines
	})

	for range failures {
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("a backend that hangs up answered %d, want 502", rec.Code)
		}
	}
	written := strings.Count(buf.String(), `msg="Proxy error"`)
	if written == 0 || written > 2*proxyErrorLinesPerSecond {
		t.Fatalf("%d failed requests wrote %d \"Proxy error\" lines, want 1..%d",
			failures, written, 2*proxyErrorLinesPerSecond)
	}
	buf.Reset()
	proxyErrorLines.Flush()
	left := 0
	for _, m := range regexp.MustCompile(`not_written=(\d+)`).FindAllStringSubmatch(buf.String(), -1) {
		n, _ := strconv.Atoi(m[1])
		left += n
	}
	if written+left != failures {
		t.Errorf("wrote %d lines and reported %d left out, want %d in all:\n%s", written, left, failures, buf.String())
	}
	if !strings.Contains(buf.String(), "target="+backend.URL) || !strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("the report does not name the target at ERROR:\n%s", buf.String())
	}
}
