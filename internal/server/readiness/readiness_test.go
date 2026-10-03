// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package readiness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gaugeValue reads g, which a test then compares.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

// resetForTest forgets every listener and the database state.
func resetForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		listeners.Lock()
		clear(listeners.failed)
		clear(listeners.bound)
		listeners.Unlock()
		entrypointUp.Reset()
		database.down.Store(nil)
	}
	reset()
	t.Cleanup(reset)
}

// TestAListenerThatFailedToBindIsNotReady: an entrypoint whose port was held
// by another process logged an error and the gateway reported ready, so a load
// balancer kept sending it the traffic of a port nothing served.
func TestAListenerThatFailedToBindIsNotReady(t *testing.T) {
	resetForTest(t)
	ListenerBound("web", ":8000")
	ListenerFailed("websecure", ":8443", errors.New("bind: address already in use"))

	got := NotReady()
	if len(got) != 1 || !strings.Contains(got[0], "websecure") || !strings.Contains(got[0], ":8443") ||
		!strings.Contains(got[0], "address already in use") {
		t.Fatalf("NotReady() = %q, want one reason naming websecure, its address and why", got)
	}
	if v := gaugeValue(t, entrypointUp.WithLabelValues("websecure")); v != 0 {
		t.Errorf("gateon_entrypoint_up{websecure} = %v, want 0", v)
	}
	if v := gaugeValue(t, entrypointUp.WithLabelValues("web")); v != 1 {
		t.Errorf("gateon_entrypoint_up{web} = %v, want 1", v)
	}
}

// TestOneFailedListenerMakesItsEntrypointDown: an HTTP/3 entrypoint has a TCP
// and a UDP listener; the TCP one binding does not hide the UDP one failing.
func TestOneFailedListenerMakesItsEntrypointDown(t *testing.T) {
	resetForTest(t)
	ListenerFailed("h3", "udp :443", errors.New("bind: permission denied"))
	ListenerBound("h3", ":443")
	if v := gaugeValue(t, entrypointUp.WithLabelValues("h3")); v != 0 {
		t.Errorf("gateon_entrypoint_up{h3} = %v with its UDP listener down, want 0", v)
	}
	if len(NotReady()) != 1 {
		t.Errorf("NotReady() = %q, want the UDP listener", NotReady())
	}
}

// TestAnUnreachableDatabaseIsNotReadyUntilItAnswers: with the configuration
// Postgres stopped, /readyz said ready and nothing showed it. It is not ready
// while the ping fails, says so without the driver's error, and recovers.
func TestAnUnreachableDatabaseIsNotReadyUntilItAnswers(t *testing.T) {
	resetForTest(t)
	down := func(context.Context) error { return errors.New("dial tcp 10.1.2.3:5432: connection refused") }
	CheckDatabase(t.Context(), down)

	got := NotReady()
	if len(got) != 1 || got[0] != databaseDownReason {
		t.Fatalf("NotReady() = %q, want [%q]", got, databaseDownReason)
	}
	if v := gaugeValue(t, configDBUp); v != 0 {
		t.Errorf("gateon_config_db_up = %v while the database is down, want 0", v)
	}

	CheckDatabase(t.Context(), func(context.Context) error { return nil })
	if got := NotReady(); len(got) != 0 {
		t.Errorf("NotReady() = %q after the database answered, want none", got)
	}
	if v := gaugeValue(t, configDBUp); v != 1 {
		t.Errorf("gateon_config_db_up = %v once the database answers, want 1", v)
	}
}

// TestShuttingDownIsNotADatabaseOutage: a ping cut short by shutdown says
// nothing about the database.
func TestShuttingDownIsNotADatabaseOutage(t *testing.T) {
	resetForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	CheckDatabase(ctx, func(c context.Context) error { return c.Err() })
	if got := NotReady(); len(got) != 0 {
		t.Errorf("NotReady() = %q after a ping cancelled by shutdown, want none", got)
	}
}

// TestWatchDatabaseChecksAtOnceAndStopsWithItsContext: the first ping is made
// at once rather than a period later, and the loop ends with ctx.
func TestWatchDatabaseChecksAtOnceAndStopsWithItsContext(t *testing.T) {
	resetForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	pinged := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		WatchDatabase(ctx, func(context.Context) error {
			select {
			case pinged <- struct{}{}:
			default:
			}
			return errors.New("down")
		})
	}()
	<-pinged // before any ticker period: the first check is immediate
	cancel()
	<-done
}
