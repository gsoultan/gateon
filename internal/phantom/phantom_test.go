// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/logger"
)

// captureLogs sends everything logged during the test to the returned buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
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

// retired names, independently of the package's own list, the variables that
// used to select an engine, so dropping one from that list fails a test.
var retired = []string{"GATEON_PHANTOM", "GATEON_XDP_IFACE"}

// resetRetiredNotice lets a test observe the once-per-process notice afresh.
func resetRetiredNotice(t *testing.T) {
	t.Helper()
	retiredNotice = sync.Once{}
	t.Cleanup(func() { retiredNotice = sync.Once{} })
}

// TestOptimizeListenerReturnsTheListenerItWasGiven pins the removal of the
// io_uring wrapper under the one setting that used to switch it on.
//
// GATEON_PHANTOM=1 made OptimizeListener return an io_uring listener in front
// of the management API and every HTTP entrypoint. Measured on two CPUs it was
// 6.7x slower per HTTP round trip and a tenth of the L4 throughput; it ignored
// read deadlines, so a Connection: close response never ended; and closing it
// did not unblock Accept, so graceful shutdown hung. The standard listener is
// what every path should get, whatever the environment says.
func TestOptimizeListenerReturnsTheListenerItWasGiven(t *testing.T) {
	_ = captureLogs(t)
	resetRetiredNotice(t)
	t.Setenv("GATEON_PHANTOM", "1")
	core := NewPhantomCore()
	defer func() { _ = core.Close() }()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	if got := core.OptimizeListener(l); got != l {
		t.Fatalf("OptimizeListener with GATEON_PHANTOM=1 returned %T, want the listener it "+
			"was given: the wrapper it used to return was slower on every benchmark and "+
			"broke deadlines and shutdown", got)
	}
}

// TestStatusClaimsNoAccelerationThatIsNotRunning pins what the Diagnostics
// page's Phantom Core card is fed: nothing here accelerates anything, so the
// status must not say it does, whatever the environment asked for.
//
// It first appended "AF_XDP" whenever it held an eBPF manager, which main
// always gave it, so every Linux install showed OPTIMIZED over the engine
// "standardAF_XDP"; later it said "io_uring" under GATEON_PHANTOM=1.
func TestStatusClaimsNoAccelerationThatIsNotRunning(t *testing.T) {
	_ = captureLogs(t)
	resetRetiredNotice(t)
	t.Setenv("GATEON_PHANTOM", "1")
	t.Setenv("GATEON_XDP_IFACE", "eth0")
	core := NewPhantomCore()
	defer func() { _ = core.Close() }()

	enabled, engine, ports := core.GetStatus()
	if enabled {
		t.Errorf("GetStatus reports enabled (engine %q): the dashboard shows OPTIMIZED while "+
			"nothing is", engine)
	}
	for _, claim := range []string{"io_uring", "AF_XDP"} {
		if strings.Contains(engine, claim) {
			t.Errorf("GetStatus reports engine %q, but no %s path exists", engine, claim)
		}
	}
	if ports != 0 {
		t.Errorf("GetStatus reports %d active phantom ports; nothing registers one", ports)
	}
}

// TestRetiredSwitchesSayTheyDoNothingOnce: an operator who set GATEON_PHANTOM=1
// switched something on. Ignoring it in silence leaves them believing it is
// still on, so startup says it does nothing -- once, not once per core built.
func TestRetiredSwitchesSayTheyDoNothingOnce(t *testing.T) {
	for _, name := range retired {
		t.Run(name, func(t *testing.T) {
			buf := captureLogs(t)
			resetRetiredNotice(t)
			for _, other := range retired {
				t.Setenv(other, "")
			}
			t.Setenv(name, "1")

			_ = NewPhantomCore()
			_ = NewPhantomCore()

			if n := strings.Count(buf.String(), "no longer change anything"); n != 1 {
				t.Fatalf("%s=1 produced %d notices over two cores, want exactly 1:\n%s", name, n, buf)
			}
			if !strings.Contains(buf.String(), "variable="+name) {
				t.Errorf("the notice does not name %s:\n%s", name, buf)
			}
		})
	}
}

// TestNoNoticeWithoutARetiredSwitch keeps the notice from becoming noise on
// every install that never set either variable.
func TestNoNoticeWithoutARetiredSwitch(t *testing.T) {
	buf := captureLogs(t)
	resetRetiredNotice(t)
	for _, name := range retired {
		t.Setenv(name, "")
	}

	_ = NewPhantomCore()

	if strings.Contains(buf.String(), "no longer change anything") {
		t.Fatalf("a notice was logged with neither variable set:\n%s", buf)
	}
}
