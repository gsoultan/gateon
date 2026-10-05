// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bytes"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gsoultan/gateon/internal/logger"
)

// captureWAFLog points logger.L at a buffer and gives the decision lines fresh
// limiters, so lines another test spent this second do not count here.
func captureWAFLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevShim, prevDefault := logger.L, slog.Default()
	prevBlock, prevWould := wafBlockLines, wafWouldBlockLines
	logger.L = &logger.SlogShim{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	wafBlockLines = newWAFLines("waf block summary")
	wafWouldBlockLines = newWAFLines("waf would-block summary")
	t.Cleanup(func() {
		logger.L = prevShim
		slog.SetDefault(prevDefault)
		wafBlockLines, wafWouldBlockLines = prevBlock, prevWould
	})
	return &buf
}

// counterSum sums a counter family's series whose route label is routeID.
func counterSum(t *testing.T, family, routeID string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "route" && l.GetValue() == routeID {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return total
}

var notWrittenRe = regexp.MustCompile(`not_written=(\d+)`)

// summarised is the sum of not_written over the lines of buf.
func summarised(buf string) int {
	n := 0
	for _, m := range notWrittenRe.FindAllStringSubmatch(buf, -1) {
		v, _ := strconv.Atoi(m[1])
		n += v
	}
	return n
}

// TestWAFDecisionLinesAreRateLimitedAndTheCountersExact is DP-N3: one INFO
// line per WAF block or would-block, so one client sending attacks wrote one
// line per request -- 20000 a second -- past journald's budget, which then
// dropped the service's ERRORs too. 200 attacks write at most two seconds'
// worth of lines (twenty), the counters move by exactly 200, and the report
// accounts for every line left out.
func TestWAFDecisionLinesAreRateLimitedAndTheCountersExact(t *testing.T) {
	const attacks = 200
	cases := map[string]struct {
		handler func(t *testing.T, route string) http.Handler
		line    string
		family  string
		limiter func() *logger.LineLimiter
		status  int
	}{
		"enforcing": {
			handler: func(t *testing.T, route string) http.Handler {
				mw, err := WAF(WAFConfig{ParanoiaLevel: 1, RouteID: route, DisableWordPress: true})
				if err != nil {
					t.Fatalf("create WAF: %v", err)
				}
				return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
			},
			line: "WAF blocked a request", family: "gateon_request_failures_total",
			limiter: func() *logger.LineLimiter { return wafBlockLines }, status: http.StatusForbidden,
		},
		"audit-only": {
			handler: func(t *testing.T, route string) http.Handler { return auditOnlyHandler(t, route, false) },
			line:    "WAF would have blocked a request", family: "gateon_middleware_waf_would_block_total",
			limiter: func() *logger.LineLimiter { return wafWouldBlockLines }, status: http.StatusOK,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			route := "waf-log-rate-" + name
			buf := captureWAFLog(t)
			h := tc.handler(t, route)
			before := counterSum(t, tc.family, route)
			for range attacks {
				if got := serveAudit(h, http.MethodGet, "/?id=1%20OR%201=1--", "", ""); got != tc.status {
					t.Fatalf("attack answered %d, want %d", got, tc.status)
				}
			}
			if got := counterSum(t, tc.family, route) - before; got != attacks {
				t.Errorf("%s moved by %v for %d attacks; the counter must stay exact", tc.family, got, attacks)
			}
			written := strings.Count(buf.String(), `msg="`+tc.line)
			if written == 0 || written > 2*wafLinesPerSecond {
				t.Fatalf("%d attacks wrote %d %q lines, want 1..%d", attacks, written, tc.line, 2*wafLinesPerSecond)
			}
			buf.Reset()
			tc.limiter().Flush()
			if left := summarised(buf.String()); written+left != attacks {
				t.Errorf("wrote %d lines and reported %d left out, want %d in all:\n%s",
					written, left, attacks, buf.String())
			}
			if !strings.Contains(buf.String(), "route="+route) {
				t.Errorf("the report does not name the route:\n%s", buf.String())
			}
		})
	}
}
