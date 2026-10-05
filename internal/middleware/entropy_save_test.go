// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// entropyThreats serves body through a body-entropy middleware the factory
// built from cfg, from a non-loopback client, and returns how many
// high_entropy_payload threats it recorded.
func entropyThreats(t *testing.T, cfg map[string]string, body string) int {
	t.Helper()
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "entropy.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{Id: "e", Type: "entropy", Config: cfg}, "api")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/orders", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.20:40000"
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).
		ServeHTTP(httptest.NewRecorder(), req)
	telemetry.FlushThreats()
	n := 0
	for len(threats) > 0 {
		if th := <-threats; th.Type == "high_entropy_payload" {
			n++
		}
	}
	return n
}

// TestBodyEntropyWithNoThresholdUsesTheDefault is review-3 F5: the editor
// shows 7.5, but the factory read an unset threshold as 0, which every body
// exceeds, so a Body Entropy middleware created from the picker recorded every
// request with a body as a high-severity threat. Unset now means 7.5: an
// ordinary JSON body is not recorded, and a random one still is.
func TestBodyEntropyWithNoThresholdUsesTheDefault(t *testing.T) {
	t.Run("text body", func(t *testing.T) {
		body := `{"order":42,"items":["book","pen"],"note":"leave at the door"}`
		if n := entropyThreats(t, map[string]string{}, body); n != 0 {
			t.Errorf("an ordinary JSON body was recorded as a high-entropy payload %d time(s) with the threshold unset", n)
		}
	})
	t.Run("random body", func(t *testing.T) {
		b := make([]byte, 4096)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if n := entropyThreats(t, map[string]string{"threshold": ""}, string(b)); n != 1 {
			t.Errorf("a random body was recorded %d time(s), want 1: the default must still detect", n)
		}
	})
}

// TestBodyEntropyThresholdOutOfRangeIsRefusedAtSave: a threshold at or below 0
// records every body and one above 8 records none, so neither is what the
// setting says; both are refused at save, on every transport (Validate is the
// domain service's check), with the range and what empty means.
func TestBodyEntropyThresholdOutOfRangeIsRefusedAtSave(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	validate := func(v string) error {
		return f.Validate(&gateonv1.Middleware{Id: "e", Type: "entropy", Config: map[string]string{"threshold": v}})
	}
	for _, v := range []string{"0", "-1", "8.01", "NaN", "+Inf"} {
		err := validate(v)
		if err == nil || !strings.Contains(err.Error(), "above 0 and at most 8") || !strings.Contains(err.Error(), "empty for 7.5") {
			t.Errorf("threshold %q: err = %v, want the save refused with the range and the default", v, err)
		}
	}
	for _, v := range []string{"", "7.5", "8", "0.5"} {
		if err := validate(v); err != nil {
			t.Errorf("threshold %q was refused: %v", v, err)
		}
	}
}
