// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// threatGuest is a hand-assembled module equivalent to
//
//	(module
//	  (import "env" "record_threat" (func (param i32 i32 i32 i32 f64)))
//	  (memory (export "memory") 1)
//	  (data (i32.const 0) "probe")
//	  (data (i32.const 16) "d")
//	  (func (export "handle")
//	    (call 0 (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 1) (f64.const SCORE))))
//
// with SCORE the score the guest records.
func threatGuest(score float64) []byte {
	var f64 [8]byte
	binary.LittleEndian.PutUint64(f64[:], math.Float64bits(score))
	module := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
		// type: (i32 i32 i32 i32 f64) -> (), () -> ()
		0x01, 0x0c, 0x02, 0x60, 0x05, 0x7f, 0x7f, 0x7f, 0x7f, 0x7c, 0x00, 0x60, 0x00, 0x00,
		// import: env.record_threat, type 0
		0x02, 0x15, 0x01, 0x03, 'e', 'n', 'v', 0x0d,
		'r', 'e', 'c', 'o', 'r', 'd', '_', 't', 'h', 'r', 'e', 'a', 't', 0x00, 0x00,
		// function: one, type 1
		0x03, 0x02, 0x01, 0x01,
		// memory: min 1 page
		0x05, 0x03, 0x01, 0x00, 0x01,
		// export: "memory" (memory 0), "handle" (func 1)
		0x07, 0x13, 0x02,
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
		0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x01,
		// code: record_threat(0, 5, 16, 1, SCORE)
		0x0a, 0x17, 0x01, 0x15, 0x00,
		0x41, 0x00, 0x41, 0x05, 0x41, 0x10, 0x41, 0x01, 0x44,
	}
	module = append(module, f64[:]...)
	return append(module,
		0x10, 0x00, 0x0b,
		// data: "probe" at 0, "d" at 16
		0x0b, 0x11, 0x02,
		0x00, 0x41, 0x00, 0x0b, 0x05, 'p', 'r', 'o', 'b', 'e',
		0x00, 0x41, 0x10, 0x0b, 0x01, 'd',
	)
}

// pluginBuild is the browser build the client presents.
const pluginBuild = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// TestAPluginsThreatIsObservedAndBounded is ADR 0059 for the WASM host. A
// guest cannot refuse a request -- the host gives it no way to -- so whatever
// it records is about a request the gateway let through. The host took the
// score as given and held it against the client: one record_threat of 1e9
// had the reputation blocker refuse the client on its next request, on every
// route. It also filed the threat under the peer address with its port, and
// under whatever route the client named in X-Gateon-Route-ID.
func TestAPluginsThreatIsObservedAndBounded(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "guest.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	for i, score := range []float64{1e9, math.Inf(1), math.NaN(), -5, 40} {
		client := fmt.Sprintf("100.64.%d.1", 30+i)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(pluginBuild, client)) })
		mw, err := Wasm(t.Context(), threatGuest(score), "plugin-route")
		if err != nil {
			t.Fatalf("build the guest: %v", err)
		}
		h := kind.Chain(identity.ReputationBlocker("plugin-route"), mw)(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

		for n := range 3 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = client + ":40000"
			req.Header.Set("X-Gateon-Route-ID", "chosen-by-the-client")
			req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: pluginBuild}))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			telemetry.FlushThreats()
			if rr.Code != http.StatusOK {
				t.Fatalf("score %v: request %d got %d: the guest's threat was held against the client",
					score, n+1, rr.Code)
			}
		}
		if len(threats) == 0 {
			t.Fatalf("score %v: the guest recorded nothing, so the assertions above prove nothing", score)
		}
		for len(threats) > 0 {
			th := <-threats
			if th.HeldAgainstSource() {
				t.Errorf("score %v: the guest's threat is held against its source", score)
			}
			if !(th.Score >= 0 && th.Score <= maxGuestThreatScore) {
				t.Errorf("score %v: recorded as %v, outside 0..%d", score, th.Score, maxGuestThreatScore)
			}
			if th.SourceIP != client || th.RouteID != "plugin-route" || th.Type != "probe" {
				t.Errorf("score %v: filed as type %q from %q on route %q, want probe from %q on plugin-route",
					score, th.Type, th.SourceIP, th.RouteID, client)
			}
		}
	}
}
