// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestFreshCodeSurvivesAStepBoundary pins the cause of the intermittent
// TestEnrollPendingRejectedOnceEnrolled failure: the helper that makes a code
// must make one that is still accepted when the clock crosses a thirty-second
// boundary before the code is checked. The clock here starts half a second
// before a boundary and moves on a second every time it is read, which is
// what a loaded CI host does to a code made at the end of a step.
func TestFreshCodeSurvivesAStepBoundary(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "quinn", "pw-123456-long")
	e, err := m.Setup2FA(id, "pw-123456-long")
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}

	boundary := time.Unix((time.Now().Unix()/30+1)*30, 0)
	var reads atomic.Int64
	m.SetClock(func() time.Time {
		return boundary.Add(-500*time.Millisecond + time.Duration(reads.Add(1)-1)*time.Second)
	})

	code, err := freshCode(t, m, e.Secret)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if ok, _, _, err := m.Verify2FA(e.Challenge, id, code); !ok || err != nil {
		t.Fatalf("the code freshCode made was refused after a step boundary: ok=%v err=%v", ok, err)
	}
}
