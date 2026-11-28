// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package bypasswatch

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func collect(w *Watch) *[]Finding {
	var got []Finding
	w.SetSink(func(f Finding) { got = append(got, f) })
	return &got
}

func login(q string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/login?"+q, nil)
}

// TestAForwardAfterASearchIsAFinding: five different payloads refused on one
// endpoint, then one forwarded there, is the search ADR 0107 is about.
func TestAForwardAfterASearchIsAFinding(t *testing.T) {
	w := New(Config{MaxSources: 16, Refusals: 5})
	got := collect(w)
	const src = "198.51.100.7"
	for i := range 5 {
		w.Refused(login(""), src, "r", fmt.Sprint("payload-", i))
	}
	w.Drain()
	w.Forwarded(login("u=admin"), src, "r")
	w.Drain()
	if len(*got) != 1 {
		t.Fatalf("got %d findings, want 1", len(*got))
	}
	f := (*got)[0]
	if f.Source != src || f.Route != "r" || f.Method != http.MethodPost || f.Path != "/login" || f.Refusals != 5 {
		t.Errorf("finding %+v", f)
	}
	if f.Request == nil || f.Request.Args["u"] != "admin" {
		t.Errorf("the finding does not carry the forwarded request: %+v", f.Request)
	}

	// One finding per search: the next forward is not reported again.
	w.Forwarded(login("u=admin"), src, "r")
	w.Drain()
	if len(*got) != 1 {
		t.Errorf("a second forward after the same search was reported (%d findings)", len(*got))
	}
}

// TestWhatIsNotASearch covers the cases a finding must not come from: a
// request retried unchanged, too few payloads, another endpoint, another
// client, and a watch that is off.
func TestAClientRefusedOnceIsNotLookedAt(t *testing.T) {
	w := New(Config{MaxSources: 16, Refusals: 5})
	w.Refused(login(""), "198.51.100.12", "r", "one false positive")
	w.Drain()
	w.Forwarded(login(""), "198.51.100.12", "r")
	if len(w.in) != 0 {
		t.Error("a client refused once had its next request captured and queued")
	}
}

func TestWhatIsNotASearch(t *testing.T) {
	const src = "198.51.100.8"
	for _, tc := range []struct {
		name string
		run  func(w *Watch)
	}{
		{"the same payload retried", func(w *Watch) {
			for range 10 {
				w.Refused(login(""), src, "r", "same")
			}
			w.Forwarded(login(""), src, "r")
		}},
		{"one payload short", func(w *Watch) {
			for i := range 4 {
				w.Refused(login(""), src, "r", fmt.Sprint(i))
			}
			w.Forwarded(login(""), src, "r")
		}},
		{"a forward on another endpoint", func(w *Watch) {
			for i := range 5 {
				w.Refused(login(""), src, "r", fmt.Sprint(i))
			}
			w.Forwarded(httptest.NewRequest(http.MethodGet, "/home", nil), src, "r")
		}},
		{"a forward from another client", func(w *Watch) {
			for i := range 5 {
				w.Refused(login(""), src, "r", fmt.Sprint(i))
			}
			w.Forwarded(login(""), "203.0.113.9", "r")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := New(Config{MaxSources: 16, Refusals: 5})
			got := collect(w)
			tc.run(w)
			w.Drain()
			w.Drain()
			if len(*got) != 0 {
				t.Errorf("got %d findings, want none: %+v", len(*got), *got)
			}
		})
	}

	off := New(Config{MaxSources: 0})
	off.Refused(login(""), src, "r", "x")
	off.Forwarded(login(""), src, "r")
	off.Drain()
	if off.Enabled() || off.Found() != 0 {
		t.Error("a watch with no sources did something")
	}
}

// TestTheWatchIsBounded: past MaxSources the client refused longest ago makes
// room, a client is followed on at most maxEndpoints endpoints, and an idle
// client is forgotten -- and a forgotten client costs a forward nothing.
func TestTheWatchIsBounded(t *testing.T) {
	w := New(Config{MaxSources: 4, Refusals: 2})
	w.Refused(login(""), "192.0.2.100", "r", "a")
	w.Refused(login(""), "192.0.2.100", "r", "b")
	w.Drain()
	if _, ok := w.hot.Load("192.0.2.100"); !ok {
		t.Fatal("a source at the threshold is not in the lookup the request path reads")
	}
	for i := range 10 {
		w.Refused(login(""), fmt.Sprint("192.0.2.", i), "r", "x")
		w.Drain()
	}
	if len(w.sources) != 4 {
		t.Errorf("following %d sources, want the cap of 4", len(w.sources))
	}
	if _, ok := w.hot.Load("192.0.2.100"); ok {
		t.Error("an evicted source is still in the lookup the request path reads")
	}

	const src = "192.0.2.9"
	for i := range 3 * maxEndpoints {
		w.Refused(httptest.NewRequest(http.MethodGet, fmt.Sprint("/p", i), nil), src, "r", "x")
	}
	w.Drain()
	if n := len(w.sources[src].endpoints); n != maxEndpoints {
		t.Errorf("following %d endpoints for one source, want %d", n, maxEndpoints)
	}

	for i := range 3 * maxHashes {
		w.Refused(login(""), src, "r", fmt.Sprint(i))
	}
	w.Drain()
	for _, st := range w.sources[src].endpoints {
		if len(st.hashes) > maxHashes {
			t.Errorf("endpoint %s holds %d hashes, past the bound of %d", st.ep.path, len(st.hashes), maxHashes)
		}
	}

	w.forgetIdle(time.Now().Add(2 * idle))
	if len(w.sources) != 0 {
		t.Errorf("%d sources survived going idle", len(w.sources))
	}
	w.Forwarded(login(""), src, "r")
	if len(w.in) != 0 {
		t.Error("a forward from a client nobody follows was queued")
	}
}

// TestAFullQueueDropsAndCounts: nothing on the request path waits for the
// watch's goroutine.
func TestAFullQueueDropsAndCounts(t *testing.T) {
	w := New(Config{MaxSources: 16})
	for range queue + 10 {
		w.Refused(login(""), "198.51.100.10", "r", "x")
	}
	if w.Dropped() != 10 {
		t.Errorf("dropped %d, want 10", w.Dropped())
	}
}

// BenchmarkForwardedUnfollowed is what every forwarded request on a WAF route
// pays when its client is not being followed: one lock-free lookup.
func BenchmarkForwardedUnfollowed(b *testing.B) {
	w := New(Config{MaxSources: 16})
	w.Refused(login(""), "198.51.100.11", "r", "x")
	w.Drain()
	r := login("")
	b.ReportAllocs()
	for b.Loop() {
		w.Forwarded(r, "203.0.113.50", "r")
	}
}
