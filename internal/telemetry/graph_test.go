// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
)

// TestAddGraphEdgeBoundsNeighborsWhenWeightsAccumulate: fingerprint edges are
// inserted at weight 2.0 and path edges reach 2.0 on their second pass, so a
// trim that only drops weights below 2.0 stops bounding the node exactly when
// an attacker keeps the traffic coming.
func TestAddGraphEdgeBoundsNeighborsWhenWeightsAccumulate(t *testing.T) {
	node := "fp:" + t.Name()
	for i := range 2000 {
		AddGraphEdge(node, fmt.Sprintf("203.0.113.%d-%d", i%256, i), 2.0)
	}
	if got := len(GetGraphSnapshot()[node]); got > 1000 {
		t.Fatalf("node holds %d neighbors; the documented cap is 1000", got)
	}
}
