// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestL4PolicyAsTheDashboardSpellsIt resolves a TCP route whose service the
// dashboard saved with "leastConn" -- its "Least Connections (TCP)" choice. The
// TCP balancer switches on "least_conn", so the service was balanced round robin.
func TestL4PolicyAsTheDashboardSpellsIt(t *testing.T) {
	cfg := ConfigFromRouteService(&gateonv1.Route{Id: "tcp-route"}, &gateonv1.Service{
		Id: "tcp-svc", LoadBalancerPolicy: "leastConn",
		WeightedTargets: []*gateonv1.Target{{Url: "tcp://127.0.0.1:9001", Weight: 1}},
	})
	if cfg == nil {
		t.Fatal("no L4 config resolved")
	}
	if cfg.LoadBalancer != "least_conn" {
		t.Fatalf("policy %q reached the TCP balancer as %q, want least_conn", "leastConn", cfg.LoadBalancer)
	}
}
