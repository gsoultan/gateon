// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// namedGuest is a hand-assembled module equivalent to
//
//	(module $guest
//	  (import "env" "set_header" (func (param i32 i32 i32 i32)))
//	  (memory (export "memory") 1)
//	  (data (i32.const 0) "X-Wasm")
//	  (data (i32.const 16) "ran")
//	  (func (export "handle")
//	    (call 0 (i32.const 0) (i32.const 6) (i32.const 16) (i32.const 3))))
//
// The one property that matters is the module name in its name section:
// toolchains commonly emit one, and wazero refuses a second live instance of a
// named module in one runtime.
var namedGuest = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	// type: (i32 i32 i32 i32) -> (), () -> ()
	0x01, 0x0b, 0x02, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00,
	// import: env.set_header, type 0
	0x02, 0x12, 0x01, 0x03, 'e', 'n', 'v', 0x0a, 's', 'e', 't', '_', 'h', 'e', 'a', 'd', 'e', 'r', 0x00, 0x00,
	// function: one, type 1
	0x03, 0x02, 0x01, 0x01,
	// memory: min 1 page
	0x05, 0x03, 0x01, 0x00, 0x01,
	// export: "memory" (memory 0), "handle" (func 1)
	0x07, 0x13, 0x02,
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
	0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x01,
	// code: set_header(0, 6, 16, 3)
	0x0a, 0x0e, 0x01, 0x0c, 0x00, 0x41, 0x00, 0x41, 0x06, 0x41, 0x10, 0x41, 0x03, 0x10, 0x00, 0x0b,
	// data: "X-Wasm" at 0, "ran" at 16
	0x0b, 0x14, 0x02,
	0x00, 0x41, 0x00, 0x0b, 0x06, 'X', '-', 'W', 'a', 's', 'm',
	0x00, 0x41, 0x10, 0x0b, 0x03, 'r', 'a', 'n',
	// custom "name" section, module-name subsection: "guest"
	0x00, 0x0d, 0x04, 'n', 'a', 'm', 'e', 0x00, 0x06, 0x05, 'g', 'u', 'e', 's', 't',
}

// TestWasmRunsForConcurrentRequests covers a WASM middleware serving two
// requests at once, which is every busy route.
//
// Each request instantiated the module and kept the instance until the rest
// of the chain -- the proxied backend included -- had returned. Instantiating
// without naming the instance gives it the module's own name, and wazero will
// not hold two instances of one name, so while one request was in flight
// every other request failed to instantiate, was logged, and went on to the
// backend without the guest having run. A guest that filters or tags traffic
// did so for one request at a time and waved the rest through.
func TestWasmRunsForConcurrentRequests(t *testing.T) {
	mw, err := Wasm(t.Context(), namedGuest)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	first := make(chan struct{})
	release := make(chan struct{})
	seen := make(chan string, 2)
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Wasm")
		if r.URL.Path == "/slow" {
			close(first)
			<-release // a backend still answering: the instance stays alive
		}
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))
	}()
	select {
	case <-first:
	case <-time.After(10 * time.Second):
		t.Fatal("the first request never reached the backend")
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/fast", nil))
	close(release)
	<-done

	for i := range 2 {
		if got := <-seen; got != "ran" {
			t.Fatalf("request %d reached the backend with X-Wasm=%q, want \"ran\": "+
				"the guest did not run for a request that overlapped another", i+1, got)
		}
	}
}
