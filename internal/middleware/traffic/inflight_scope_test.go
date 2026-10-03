// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// holdingBackend holds every request carrying X-Hold until release is closed,
// and signals each one it admits; any other request answers at once.
type holdingBackend struct {
	entered chan struct{}
	release chan struct{}
}

func (b *holdingBackend) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Hold") != "" {
		b.entered <- struct{}{}
		<-b.release
	}
}

func heldRequest(remote, host string, hold bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	r.RemoteAddr = remote
	if hold {
		r.Header.Set("X-Hold", "1")
	}
	return r
}

// holdN starts n held requests through h, each from its own address and Host,
// and returns once all are inside the backend; release lets them finish.
func holdN(t *testing.T, h http.Handler, b *holdingBackend, n int) {
	t.Helper()
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			h.ServeHTTP(httptest.NewRecorder(), heldRequest("192.0.2."+string(rune('1'+i))+":1", "h"+string(rune('a'+i))+".test", true))
		})
	}
	for range n {
		<-b.entered
	}
	t.Cleanup(func() { close(b.release); wg.Wait() })
}

// TestInflightTotalCapIsATotal: with per_ip=false the cap was keyed on the
// request's Host, which the client writes, so every distinct Host got its own
// allowance and the backend saw amount x hosts. Off per-address, the cap is one
// count for the route the middleware is attached to.
func TestInflightTotalCapIsATotal(t *testing.T) {
	mw, err := NewInflightReq(map[string]string{"amount": "2", "per_ip": "false"})
	if err != nil {
		t.Fatal(err)
	}
	b := &holdingBackend{entered: make(chan struct{}), release: make(chan struct{})}
	h := mw(b)
	holdN(t, h, b, 2)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, heldRequest("198.51.100.9:1", "elsewhere.test", false))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a third concurrent request from a new address and Host got %d, want 503: "+
			"the total of 2 was exceeded", rec.Code)
	}
}

// TestInflightPerAddressIsPerAddress: the default counts each client address
// on its own -- what the dashboard now says.
func TestInflightPerAddressIsPerAddress(t *testing.T) {
	mw, err := NewInflightReq(map[string]string{"amount": "1"})
	if err != nil {
		t.Fatal(err)
	}
	b := &holdingBackend{entered: make(chan struct{}), release: make(chan struct{})}
	h := mw(b)
	holdN(t, h, b, 1) // 192.0.2.1 holds its one slot

	other := httptest.NewRecorder()
	h.ServeHTTP(other, heldRequest("198.51.100.9:1", "ha.test", false))
	same := httptest.NewRecorder()
	h.ServeHTTP(same, heldRequest("192.0.2.1:2", "ha.test", false))
	if other.Code != http.StatusOK || same.Code != http.StatusTooManyRequests {
		t.Fatalf("another address got %d (want 200), the same address got %d (want 429)", other.Code, same.Code)
	}
}
