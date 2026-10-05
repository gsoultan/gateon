// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	accessLogs = accessLogCap{}
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
// writes again, and a minute on the cap says how many lines it held back.
func TestTheAccessLogCapResetsEachSecondAndReportsWhatItLeftOut(t *testing.T) {
	buf := captureLog(t)
	var c accessLogCap
	c.setMax(2)
	t0 := time.Now().Add(time.Hour)
	c.reported.Store(int64(t0.Sub(accessLogEpoch)))

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

// TestTheAccessLogCapHoldsWhenRequestsFinishOutOfOrder is OPS-N2: the cap was
// keyed on the time each request started and reset its count whenever that
// differed from the second it held, forwards or backwards. A slow request
// finishing beside fast ones moved the second back, the next fast one moved it
// forward, and every move started the count over: 737 lines a second through
// a cap of 100. Two seconds' worth (twenty) is the most that may pass here.
func TestTheAccessLogCapHoldsWhenRequestsFinishOutOfOrder(t *testing.T) {
	captureLog(t)
	var c accessLogCap
	c.setMax(10)
	base := time.Now()
	earlier, later := base.Add(time.Second), base.Add(2*time.Second)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				at := later
				if (i+g)%2 == 1 {
					at = earlier
				}
				if c.allow(at) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := allowed.Load(); n > 20 {
		t.Fatalf("%d of 4000 access-log lines written across two seconds under a cap of 10 a second", n)
	}
}

// TestAZeroCapLiftsIt: GATEON_ACCESS_LOG_MAX_PER_SECOND=0 writes every line.
func TestAZeroCapLiftsIt(t *testing.T) {
	t.Setenv(accessLogMaxPerSecondEnv, "0")
	if got := accessLogMaxPerSecond(); got != 0 {
		t.Fatalf("accessLogMaxPerSecond() = %d, want 0", got)
	}
	var c accessLogCap
	c.setMax(accessLogMaxPerSecond())
	for range 1000 {
		if !c.allow(time.Now()) {
			t.Fatal("a zero cap refused a line")
		}
	}
}

// BenchmarkAccessLogCapAllow is the per-request cost of the cap on a line
// that would be written: an atomic load and add, no allocation.
func BenchmarkAccessLogCapAllow(b *testing.B) {
	var c accessLogCap
	c.setMax(1 << 23)
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.allow(now)
		}
	})
}
