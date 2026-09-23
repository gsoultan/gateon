// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestPolicyIsSafeUnderConcurrentRequests: Policy compiles each rule once and
// shares the cel-go Program across every request on the route, so if Eval
// mutated program state this would be a data race on the request path -- the
// kind that surfaces under load and never in a serial test.
func TestPolicyIsSafeUnderConcurrentRequests(t *testing.T) {
	mw, err := Policy(PolicyConfig{Rules: []PolicyRule{{
		Expression: `request.path != "/admin" && request.method != "TRACE"`,
		Message:    "denied",
	}}})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const workers, iterations = 8, 25
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range iterations {
				// Half allowed, half denied, so both branches run concurrently.
				path := fmt.Sprintf("/ok/%d/%d", w, i)
				want := http.StatusOK
				if i%2 == 0 {
					path = "/admin"
					want = http.StatusForbidden
				}
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
				if rr.Code != want {
					t.Errorf("worker %d iter %d: path %s got %d, want %d", w, i, path, rr.Code, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}
