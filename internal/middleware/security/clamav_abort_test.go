// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// silentClamd accepts connections, reads whatever is streamed at it and never
// answers, so every scan against it reaches scanStream's timeout. It is the
// case the abort channel exists for.
func silentClamd(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return "tcp://" + ln.Addr().String()
}

// settledGoroutines polls until the count stops falling, so a goroutine that is
// on its way out is not counted as a leak.
func settledGoroutines(target int) int {
	deadline := time.Now().Add(5 * time.Second)
	n := runtime.NumGoroutine()
	for time.Now().Before(deadline) && n > target {
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

// TestScanStreamReleasesGoroutinesOnTimeout pins the abort contract.
//
// go-clamd's ScanStream spawns a watcher written as
//
//	for { _, allowRunning := <-abort; if !allowRunning { break } }
//	conn.Close()
//
// which breaks only when abort is *closed*. scanStream used to send `true`,
// which that loop reads as "keep running" and discards -- so the abort did
// nothing. The watcher blocked on <-abort forever, the connection was never
// torn down, and the response channel scanStream's own goroutine was ranging
// over never closed. Two goroutines per scanned part, for the life of the
// process, on exactly the path a slow or hostile upload takes.
func TestScanStreamReleasesGoroutinesOnTimeout(t *testing.T) {
	addr := silentClamd(t)
	cfg := FileSecurityConfig{ClamAVAddr: addr, ScanTimeout: 100 * time.Millisecond}
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)

	// One scan first, so the listener's own accept goroutine and any lazy
	// runtime machinery are already up and not counted as growth.
	if _, err := scanStream(req, cfg, bytes.NewReader([]byte("seed"))); err == nil {
		t.Fatal("expected the silent collector to time the scan out")
	}
	baseline := settledGoroutines(0)

	const scans = 20
	for range scans {
		if _, err := scanStream(req, cfg, bytes.NewReader([]byte("payload"))); err == nil {
			t.Fatal("expected the silent collector to time the scan out")
		}
	}

	after := settledGoroutines(baseline)
	if grew := after - baseline; grew > scans/4 {
		t.Errorf("%d scans that timed out left %d goroutines behind (%d -> %d); "+
			"the abort channel must be closed, not signalled -- a send reads as "+
			"\"keep running\" to go-clamd's watcher",
			scans, grew, baseline, after)
	}
}
