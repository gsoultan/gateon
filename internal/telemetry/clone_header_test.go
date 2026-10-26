// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"reflect"
	"testing"
)

// CloneHeader runs twice per traced request, and at the standard tier every
// request is traced. It allocated one slice per header name, ten for a plain
// browser request; it now cuts every value list from one backing array. The
// copy must stay a copy: appending to one cloned list must not write into
// the next, and nil lists must stay nil so FormatHeaders prints them as before.
func TestCloneHeaderCopiesEveryValueIntoTwoAllocations(t *testing.T) {
	in := http.Header{
		"Accept":     {"text/html", "*/*"},
		"User-Agent": {"Mozilla/5.0"},
		"Cookie":     {"a=1"},
		"X-Empty":    nil,
		"X-Zero":     {},
	}
	got := CloneHeader(in)
	if !reflect.DeepEqual(got, map[string][]string(in)) {
		t.Fatalf("clone differs from the original:\n got %v\nwant %v", got, in)
	}
	if got["X-Empty"] != nil {
		t.Fatalf("nil value list became %#v", got["X-Empty"])
	}

	in["Accept"][0] = "changed"
	if got["Accept"][0] != "text/html" {
		t.Fatal("clone shares the original's value slice")
	}
	got["Cookie"] = append(got["Cookie"], "b=2")
	for name, vals := range got {
		if name != "Cookie" && len(vals) > 0 && vals[len(vals)-1] == "b=2" {
			t.Fatalf("appending to Cookie wrote into %s", name)
		}
	}

	// The map itself is one or two allocations depending on its size; the
	// values are one, whatever the header count.
	if n := testing.AllocsPerRun(100, func() { CloneHeader(in) }); n > 3 {
		t.Fatalf("CloneHeader allocated %v times for %d headers, want the map and one backing array", n, len(in))
	}
	if CloneHeader(nil) != nil {
		t.Fatal("cloning nil must stay nil")
	}
}

// The header-kind memo caches a classification keyed by a name the client
// wrote, so it must stay bounded: past headerKindMemoMax names it starts
// over rather than growing, and a name longer than any real header is
// classified without being remembered.
func TestHeaderKindMemoIsBounded(t *testing.T) {
	headerKindMemo.mu.Lock()
	headerKindMemo.m = nil
	headerKindMemo.mu.Unlock()

	for i := range headerKindMemoMax * 3 {
		name := "X-Hostile-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
		if headerKindOf(name) != headerPlain {
			t.Fatalf("%s classified as something other than plain", name)
		}
	}
	headerKindMemo.mu.RLock()
	size := len(headerKindMemo.m)
	headerKindMemo.mu.RUnlock()
	if size > headerKindMemoMax {
		t.Fatalf("memo holds %d names, bound is %d", size, headerKindMemoMax)
	}

	long := make([]byte, headerKindMemoNameMax+1)
	for i := range long {
		long[i] = 'x'
	}
	if headerKindOf(string(long)) != headerPlain {
		t.Fatal("an over-long name must still be classified")
	}
	headerKindMemo.mu.RLock()
	_, kept := headerKindMemo.m[string(long)]
	headerKindMemo.mu.RUnlock()
	if kept {
		t.Fatal("an over-long name was remembered")
	}

	// The memo must agree with the classifier it stands in for.
	for _, name := range []string{"Authorization", "Cookie", "Referer", "User-Agent", "authorization"} {
		if headerKindOf(name) != classifyHeader(name) {
			t.Fatalf("memo disagrees with classifyHeader on %s", name)
		}
	}
}
