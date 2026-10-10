// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// tarpitSaveFixture is testdata/tarpit_save.json, which the dashboard's test
// (ui/src/components/MiddlewareConfig/tarpitSave.test.ts) reads too.
type tarpitSaveFixture struct {
	Messages map[string]string `json:"messages"`
	Cases    []struct {
		Name    string            `json:"name"`
		Config  map[string]string `json:"config"`
		Refused string            `json:"refused"`
	} `json:"cases"`
}

// gatewayForm is how the gateway says what the dashboard says: an error
// string starts lower-case and ends without a full stop.
func gatewayForm(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// TestTarpitSaveRuleMatchesTheDashboard holds the save check to the
// dashboard's rule. The dashboard refused a tarpit without a threshold above
// 0 and a maximum delay (ADR 0063); the gateway saved one from the API or an
// import, and the factory read the unset threshold as 0.
func TestTarpitSaveRuleMatchesTheDashboard(t *testing.T) {
	raw, err := os.ReadFile("testdata/tarpit_save.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx tarpitSaveFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if got, want := TarpitThresholdRequired, gatewayForm(fx.Messages["threshold"]); got != want {
		t.Errorf("TarpitThresholdRequired = %q, want the dashboard's %q", got, want)
	}
	if got, want := TarpitMaxDelayRequired, gatewayForm(fx.Messages["max_delay"]); got != want {
		t.Errorf("TarpitMaxDelayRequired = %q, want the dashboard's %q", got, want)
	}
	if len(fx.Cases) < 10 {
		t.Fatalf("%d cases read; the fixture did not parse as expected", len(fx.Cases))
	}
	for _, c := range fx.Cases {
		err := CheckTarpitSave(c.Config)
		switch {
		case c.Refused == "" && err != nil:
			t.Errorf("%s: refused (%v); the dashboard saves it", c.Name, err)
		case c.Refused == "":
		case err == nil:
			t.Errorf("%s: saved; the dashboard refuses it for %s", c.Name, c.Refused)
		case !strings.Contains(err.Error(), `"`+c.Refused+`"`) ||
			!strings.HasSuffix(err.Error(), gatewayForm(fx.Messages[c.Refused])):
			t.Errorf("%s: refused as %q, want key %q and the dashboard's words", c.Name, err, c.Refused)
		}
	}
}

// penalisedRequest is a request from a client whose threat score is 50.
func penalisedRequest(t *testing.T, peer string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer + ":4444"
	id := telemetry.GetReputationID(req)
	telemetry.DecreaseReputation(id, 50, "test: tarpit")
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	if got := 100 - telemetry.GetReputationScore(id); got != 50 {
		t.Fatalf("threat score %v, want 50; the rest of this test would prove nothing", got)
	}
	return req
}

// served reports how long h took to answer req.
func served(h http.Handler, req *http.Request) time.Duration {
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), req)
	return time.Since(start)
}

// TestStoredTarpitWithoutAThresholdIsOff is the build-time half. A tarpit
// stored before the save check, with no threshold, compared every client's
// threat score with 0 and divided by it: on arm64 every client with any threat
// score was held for the maximum delay, on amd64 none was. It is built off --
// delaying nobody, on every platform -- and says why, so the router can
// report it.
func TestStoredTarpitWithoutAThresholdIsOff(t *testing.T) {
	const delay = 300 * time.Millisecond
	for _, tc := range []struct {
		name string
		cfg  map[string]string
		peer string
	}{
		{"no threshold", map[string]string{"base_delay": "300ms", "max_delay": "300ms"}, "100.64.91.1"},
		{"threshold 0", map[string]string{"threshold": "0", "base_delay": "300ms", "max_delay": "300ms"}, "100.64.93.1"},
		{"no maximum delay", map[string]string{"threshold": "7", "base_delay": "300ms"}, "100.64.94.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if CheckTarpitSave(tc.cfg) == nil {
				t.Fatal("the save check accepts this config; it is not one only a stored config can hold")
			}
			mw, err := NewTarpit(tc.cfg)
			if err != nil {
				t.Fatalf("a stored tarpit must keep building: %v", err)
			}
			h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			if took := served(h, penalisedRequest(t, tc.peer)); took >= delay {
				t.Errorf("a client with threat score 50 was held %v; the tarpit must be off", took)
			}
			if TarpitOff(tc.cfg) == "" {
				t.Error("TarpitOff names no reason, so nothing would report the tarpit as off")
			}
		})
	}
	if why := TarpitOff(map[string]string{"threshold": "7", "max_delay": "5s"}); why != "" {
		t.Errorf("a valid tarpit is reported off: %s", why)
	}
}

// TestTarpitDelayIsCappedNotOverflowed: the delay is the base delay scaled by
// score/threshold, which for a small threshold runs past the range of a
// Duration. Converted first and capped after, it came out negative on amd64,
// so the worst clients were not delayed at all.
func TestTarpitDelayIsCappedNotOverflowed(t *testing.T) {
	const delay = 200 * time.Millisecond
	h := Tarpit(time.Second, delay, 1e-12)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if took := served(h, penalisedRequest(t, "100.64.92.1")); took < delay {
		t.Errorf("a client with threat score 50 over a threshold of 1e-12 was held %v, want the maximum %v", took, delay)
	}
	if got := tarpitDelay(time.Second, delay, 5e13); got != delay {
		t.Errorf("tarpitDelay past the Duration range = %v, want the cap %v", got, delay)
	}
}
