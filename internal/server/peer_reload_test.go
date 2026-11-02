// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// reloadRecorder notes the order in which registries are reloaded and caches
// cleared. The order is the point: a cache cleared first is rebuilt from the
// registry as it was.
type reloadRecorder struct {
	events []string
	fail   bool
}

func (r *reloadRecorder) Reload(context.Context) error {
	r.events = append(r.events, "reload")
	if r.fail {
		return errors.New("database away")
	}
	return nil
}
func (r *reloadRecorder) InvalidateRoute(string) { r.events = append(r.events, "invalidate") }
func (r *reloadRecorder) InvalidateRoutes(func(*gateonv1.Route) bool) {
	r.events = append(r.events, "invalidate")
}
func (r *reloadRecorder) InvalidateTLS() { r.events = append(r.events, "invalidate") }
func (r *reloadRecorder) InvalidateWAF() { r.events = append(r.events, "invalidate") }

// A peer's message cleared this node's caches, which were rebuilt from
// registries read once at start-up, so the change the message announced was
// never served here. The registries the message concerns are now re-read
// first.
func TestAPeersInvalidationReloadsBeforeItClearsCaches(t *testing.T) {
	for _, tc := range []struct {
		msgType string
		want    []string
	}{
		{"route", []string{"reload", "invalidate"}},
		{"all", []string{"reload", "invalidate"}},
		{"tls", []string{"reload", "invalidate"}},
		{"waf", []string{"reload", "invalidate"}},
	} {
		t.Run(tc.msgType, func(t *testing.T) {
			rec := &reloadRecorder{}
			p := &peerReloaders{
				config: []namedReloader{{name: "routes", r: rec}},
				waf:    []namedReloader{{name: "waf rules", r: rec}},
			}
			handleInvalidation(context.Background(), InvalidationMessage{Type: tc.msgType, ID: "r1", NodeID: "other-node"}, rec, nil, p)
			if len(rec.events) != len(tc.want) {
				t.Fatalf("%s: events %v, want %v", tc.msgType, rec.events, tc.want)
			}
			for i := range tc.want {
				if rec.events[i] != tc.want[i] {
					t.Fatalf("%s: events %v, want %v", tc.msgType, rec.events, tc.want)
				}
			}
		})
	}
}

// A reload that fails leaves the registry as it was and still clears the
// caches: a stale rebuild is what every message did before, and never worse.
func TestAFailedPeerReloadStillInvalidates(t *testing.T) {
	rec := &reloadRecorder{fail: true}
	p := &peerReloaders{config: []namedReloader{{name: "routes", r: rec}}}
	handleInvalidation(context.Background(), InvalidationMessage{Type: "all", NodeID: "other-node"}, rec, nil, p)
	if len(rec.events) != 2 || rec.events[1] != "invalidate" {
		t.Fatalf("events %v, want a reload then an invalidation", rec.events)
	}
}

// Our own broadcast reloads nothing: the write that caused it was ours.
func TestOurOwnBroadcastReloadsNothing(t *testing.T) {
	rec := &reloadRecorder{}
	p := &peerReloaders{config: []namedReloader{{name: "routes", r: rec}}}
	handleInvalidation(context.Background(), InvalidationMessage{Type: "all", NodeID: nodeID}, rec, nil, p)
	if len(rec.events) != 0 {
		t.Fatalf("our own message produced %v", rec.events)
	}
}
