// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestBeingChallengedIsNotHeldAgainstTheClient: serving a proof-of-work
// challenge used to be recorded as a threat. Every challenge then lowered the
// client's reputation and counted as a "challenged" action toward escalation,
// and on the built gateway one blocked attack plus one challenge correlated
// into a critical incident that zeroed the score -- so the reputation blocker
// refused the client before it could solve the challenge it had just been
// given. Invisible while T10 kept proof-of-work from firing.
//
// The barrier is a control client whose wrong answer *is* a threat, recorded
// after the challenges: the threat queue is drained in order, so once the
// control's score moves, every challenge before it has been processed.
func TestBeingChallengedIsNotHeldAgainstTheClient(t *testing.T) {
	if err := telemetry.InitPathStatsStore("sqlite:"+filepath.Join(t.TempDir(), "pow.db"), 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	h := Pow(1, 5, "s3cret", "pow-escalation")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	const client, control = "100.64.91.1", "100.64.92.1"
	clientID := telemetry.GetReputationID(penalisedRequest(t, client, 50))
	controlReq := penalisedRequest(t, control, 50)
	controlID := telemetry.GetReputationID(controlReq)

	for range 5 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, penalisedRequestAgain(client))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("a client with threat 50 at threshold 5 got %d, want the challenge", rec.Code)
		}
	}

	wrong := penalisedRequestAgain(control)
	wrong.Header.Set(PowHeaderID, "1-00-00")
	wrong.Header.Set(PowNonceHeader, "1")
	wrong.Header.Set(PowHeaderSolution, "00")
	h.ServeHTTP(httptest.NewRecorder(), wrong)
	for i := 0; telemetry.GetReputationScore(controlID) == 50; i++ {
		if i == 200 {
			t.Fatal("the control's wrong answer never reached its reputation; the barrier proves nothing")
		}
		telemetry.FlushThreats()
	}

	if got := telemetry.GetReputationScore(clientID); got != 50 {
		t.Fatalf("being challenged five times moved the client's reputation from 50 to %v", got)
	}
}

// penalisedRequestAgain is another request from a peer penalisedRequest set
// up, with the same identity.
func penalisedRequestAgain(peer string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = peer + ":4444"
	req.Header.Set("User-Agent", "pow-threshold-test")
	return req
}
