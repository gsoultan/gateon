// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestTallyTargets(t *testing.T) {
	var c telemetry.TargetHealthCounts
	TallyTargets([]TargetStats{{Alive: true}, {Alive: false}, {Alive: true}}, &c)
	TallyTargets(nil, &c)
	if want := (telemetry.TargetHealthCounts{Healthy: 2, Down: 1, Total: 3}); c != want {
		t.Fatalf("TallyTargets = %+v, want %+v", c, want)
	}
}
