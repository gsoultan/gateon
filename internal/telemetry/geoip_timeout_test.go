// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDownloadGeoIPEditionGivesUpOnAServerThatNeverAnswers: the download went
// through http.Get, which has no timeout of any kind. An endpoint that accepted
// the connection and never answered -- MaxMind under load, or whatever a
// hijacked DNS answer put at its name -- held the update worker, and the
// /v1/geoip/update request that asked for it, for the life of the process.
func TestDownloadGeoIPEditionGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var held []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // open and silent until the test ends
			mu.Unlock()
		}
	}()

	prev, prevTimeout := geoIPDownloadURL, geoIPResponseHeaderTimeout
	geoIPDownloadURL = "http://" + l.Addr().String() + "/app/geoip_download"
	geoIPResponseHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { geoIPDownloadURL, geoIPResponseHeaderTimeout = prev, prevTimeout })

	done := make(chan error, 1)
	go func() {
		done <- downloadGeoIPEdition("key", geoIPEdition{
			id:       editionCity,
			destPath: filepath.Join(t.TempDir(), "GeoLite2-City.mmdb"),
			reload:   func(string) error { return nil },
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a server that never answered was reported as a successful download")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the download is still waiting on a server that will never answer")
	}
}
