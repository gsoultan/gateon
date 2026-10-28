// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

func checkIDFormat(t *testing.T, id string) {
	t.Helper()
	hexPart, ok := strings.CutPrefix(id, "req-")
	if !ok || len(id) != idLen {
		t.Fatalf("id %q is not req- and sixteen hex digits", id)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("id %q: %v", id, err)
	}
}

// IDs cut from batches are still what GenerateID always produced, and unique
// across batch boundaries and across goroutines taking batches concurrently.
func TestGeneratedIDsAreWellFormedAndUnique(t *testing.T) {
	const goroutines, perG = 8, 10 * idBatchSize
	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*perG*2)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			local := make([]string, 0, perG*2)
			for i := range perG {
				if i%2 == 0 {
					local = append(local, GenerateID())
					continue
				}
				id, v := NewIDHeader()
				if len(v) != 1 || v[0] != id {
					t.Errorf("header value %q for id %q", v, id)
				}
				local = append(local, id)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				checkIDFormat(t, id)
				if _, dup := seen[id]; dup {
					t.Errorf("id %q handed out twice", id)
				}
				seen[id] = struct{}{}
			}
		})
	}
	wg.Wait()
}

// A header value is its own slot: capacity one, so an append under the same
// header name -- a proxy adding a second X-Request-Id -- reallocates instead of
// overwriting the value handed to the next request.
func TestIDHeaderValuesDoNotShareSlots(t *testing.T) {
	vals := make([][]string, idBatchSize+1)
	ids := make([]string, len(vals))
	for i := range vals {
		ids[i], vals[i] = NewIDHeader()
		if cap(vals[i]) != 1 {
			t.Fatalf("value capacity %d, want 1", cap(vals[i]))
		}
	}
	for i := range vals {
		vals[i] = append(vals[i], "appended")
	}
	for i := range vals {
		if vals[i][0] != ids[i] {
			t.Fatalf("value %d is %q, want its id %q", i, vals[i][0], ids[i])
		}
	}
	if v := IDHeaderValue("client-id"); len(v) != 1 || cap(v) != 1 || v[0] != "client-id" {
		t.Fatalf("supplied id's value %q (cap %d)", v, cap(v))
	}
}

// An ID and its header value cost an eighth of an allocation each. Before
// batching they cost one each, on every request.
func TestRequestIDAllocationsAreAmortised(t *testing.T) {
	if raceDetector {
		t.Skip("sync.Pool drops items under -race, so allocation counts are not meaningful")
	}
	if n := testing.AllocsPerRun(1000, func() { _, _ = NewIDHeader() }); n != 0 {
		t.Fatalf("NewIDHeader averaged %v allocations, want under one", n)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = GenerateID() }); n != 0 {
		t.Fatalf("GenerateID averaged %v allocations, want under one", n)
	}
}
