// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// captureLog points logger.L at slog's default, which this swaps for a buffer.
func captureLog(t *testing.T) *bytes.Buffer {
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

func countLines(buf *bytes.Buffer, msg string) int {
	return strings.Count(buf.String(), `msg="`+msg)
}

// TestTheAccessLogIsCappedPerSecond: one stdout line per request, uncapped,
// is what put a gateway past journald's default rate limit at ~333 req/s,
// after which journald dropped every line from the service -- its ERRORs and
// security events included. Fifty requests in a second write at most the cap
// (twice it, should the loop straddle a second).
func TestTheAccessLogIsCappedPerSecond(t *testing.T) {
	t.Setenv(accessLogMaxPerSecondEnv, "5")
	t.Cleanup(func() { accessLogs = accessLogCap{} })
	buf := captureLog(t)
	h := AccessLogSampled("capped-route", 1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for range 50 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if n := countLines(buf, "access log"); n < 5 || n > 10 {
		t.Errorf("50 requests wrote %d access-log lines under a cap of 5 a second", n)
	}
}

// TestTheAccessLogCapResetsEachSecondAndReportsWhatItLeftOut: a new second
// writes again, and a new minute says how many lines the cap held back.
func TestTheAccessLogCapResetsEachSecondAndReportsWhatItLeftOut(t *testing.T) {
	t.Cleanup(func() { accessLogs = accessLogCap{} })
	buf := captureLog(t)
	var c accessLogCap
	c.max.Store(2)
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	allowed := 0
	for range 5 {
		if c.allow(t0) {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("allowed %d of 5 lines in one second under a cap of 2", allowed)
	}
	if !c.allow(t0.Add(time.Second)) {
		t.Error("the first line of the next second was refused")
	}
	if n := countLines(buf, "access log: lines over the per-second cap"); n != 0 {
		t.Errorf("reported %d times inside the minute, want 0", n)
	}
	c.allow(t0.Add(time.Minute))
	if !strings.Contains(buf.String(), "not_written=3") {
		t.Errorf("the next minute did not report the 3 lines left out:\n%s", buf.String())
	}
}

// TestAZeroCapLiftsIt: GATEON_ACCESS_LOG_MAX_PER_SECOND=0 writes every line.
func TestAZeroCapLiftsIt(t *testing.T) {
	t.Setenv(accessLogMaxPerSecondEnv, "0")
	if got := accessLogMaxPerSecond(); got != 0 {
		t.Fatalf("accessLogMaxPerSecond() = %d, want 0", got)
	}
	var c accessLogCap
	for range 1000 {
		if !c.allow(time.Unix(1, 0)) {
			t.Fatal("a zero cap refused a line")
		}
	}
}

// BenchmarkAccessLogCapAllow is the per-request cost of the cap on a line
// that would be written: an atomic load and add, no allocation.
func BenchmarkAccessLogCapAllow(b *testing.B) {
	var c accessLogCap
	c.max.Store(1 << 62)
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.allow(now)
		}
	})
}
