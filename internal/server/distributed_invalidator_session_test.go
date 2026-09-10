// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"os"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/domain/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type recordingBindings struct{ ids []string }

func (r *recordingBindings) InvalidateBinding(id string) { r.ids = append(r.ids, id) }

type noopInvalidator struct{ calls []string }

func (n *noopInvalidator) InvalidateRoute(string) { n.calls = append(n.calls, "route") }
func (n *noopInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {
	n.calls = append(n.calls, "all")
}
func (n *noopInvalidator) InvalidateTLS() { n.calls = append(n.calls, "tls") }
func (n *noopInvalidator) InvalidateWAF() { n.calls = append(n.calls, "waf") }

var _ proxy.Invalidator = (*noopInvalidator)(nil)

func TestHandleInvalidation_SessionReachesTheBindingCache(t *testing.T) {
	b := &recordingBindings{}
	handleInvalidation(InvalidationMessage{Type: "session", ID: "user-1", NodeID: "other-node"}, &noopInvalidator{}, b)

	if len(b.ids) != 1 || b.ids[0] != "user-1" {
		t.Fatalf("expected user-1 invalidated, got %v", b.ids)
	}
}

// A node applied the change before publishing, so its own echo is noise.
func TestHandleInvalidation_SkipsItsOwnBroadcast(t *testing.T) {
	b := &recordingBindings{}
	handleInvalidation(InvalidationMessage{Type: "session", ID: "user-1", NodeID: nodeID}, &noopInvalidator{}, b)

	if len(b.ids) != 0 {
		t.Fatalf("a node must ignore its own broadcast, got %v", b.ids)
	}
}

func TestHandleInvalidation_SessionWithoutIDIsIgnored(t *testing.T) {
	b := &recordingBindings{}
	handleInvalidation(InvalidationMessage{Type: "session", NodeID: "other-node"}, &noopInvalidator{}, b)

	if len(b.ids) != 0 {
		t.Fatalf("an empty user id must not invalidate anything, got %v", b.ids)
	}
}

// The listener is shared with route/TLS/WAF invalidation; a nil bindings
// argument must not take the whole loop down.
func TestHandleInvalidation_NilBindingsIsSafe(t *testing.T) {
	handleInvalidation(InvalidationMessage{Type: "session", ID: "user-1", NodeID: "other-node"}, &noopInvalidator{}, nil)
}

func TestHandleInvalidation_StillRoutesTheOtherTypes(t *testing.T) {
	for _, tc := range []struct{ msgType, want string }{
		{"route", "route"}, {"all", "all"}, {"tls", "tls"}, {"waf", "waf"},
	} {
		inv := &noopInvalidator{}
		handleInvalidation(InvalidationMessage{Type: tc.msgType, NodeID: "other-node"}, inv, nil)
		if len(inv.calls) != 1 || inv.calls[0] != tc.want {
			t.Errorf("type %q: got %v, want [%s]", tc.msgType, inv.calls, tc.want)
		}
	}
}

// nodeID used to be os.Hostname(), so two gateon processes in two containers on
// one host read each other's invalidations as their own echo and discarded
// them — the arrangement most likely to actually be running two instances. This
// pins the identity to something narrower than the host.
func TestNodeID_IsNotJustTheHostname(t *testing.T) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("no hostname on this machine")
	}
	if nodeID == host {
		t.Fatal("nodeID equals the hostname, so two instances on one host discard each other's invalidations")
	}
	if !strings.HasPrefix(nodeID, host) {
		t.Fatalf("nodeID %q should still start with the hostname, for readability in logs", nodeID)
	}
}
