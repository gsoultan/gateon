// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalEffect is one entry of the global-setting effect registry (truth
// NEW-10, ADR 0063).
//
// The middleware registry (internal/middleware/dashboard_key_effects_test.go)
// proves a dashboard key through the factory. Global settings had no rows, so a
// global security threshold that was read and then ignored -- the PoW
// threshold made a constant, the feed's block threshold read and dropped --
// passed every gate. Each row here sets the global setting to two values,
// builds a route's chain the way the router does, sends the same probe through
// both, and requires the answers to differ. scripts/checkconfig fails when a
// global security setting it lists has neither a row here nor a line in
// scripts/checkconfig/globals-baseline.txt.
type globalEffect struct {
	field  string // the setting, as the proto spells its path
	set    func(c *gateonv1.GlobalConfig, v string)
	a, b   string
	setup  func(t *testing.T, peer string, c *gateonv1.GlobalConfig) // before each probe
	header string                                                    // a response header to record as well as the status
	inert  string                                                    // the finding that says it does nothing
}

const effectPowSecret = "global-effect-pow-secret-0123456789abcdef"

var globalSettingEffects = []globalEffect{
	{field: "security_advanced.pow.score_threshold", a: "60", b: "40",
		set:   func(c *gateonv1.GlobalConfig, v string) { powConfig(c).ScoreThreshold = mustFloat(v) },
		setup: penalise(50), header: "X-Gateon-Pow-Difficulty"},
	{field: "security_advanced.pow.difficulty", a: "1", b: "2",
		set:   func(c *gateonv1.GlobalConfig, v string) { powConfig(c).Difficulty = int32(mustFloat(v)) },
		setup: penalise(50), header: "X-Gateon-Pow-Difficulty"},
	{field: "security_advanced.ip_reputation.block_threshold", a: "80", b: "95",
		set: func(c *gateonv1.GlobalConfig, v string) {
			c.SecurityAdvanced.IpReputation = &gateonv1.IPReputationConfig{Enabled: true, BlockThreshold: mustFloat(v)}
		},
		setup: listInFeed(90)},
}

func TestGlobalSecuritySettingsChangeWhatTheGatewayDoes(t *testing.T) {
	for i, row := range globalSettingEffects {
		t.Run(row.field, func(t *testing.T) {
			withA := observeGlobal(t, row, row.a, i)
			withB := observeGlobal(t, row, row.b, i)
			switch differs := withA != withB; {
			case row.inert == "" && !differs:
				t.Errorf("%s=%q and %s=%q answer the same probe identically: %s; the setting has no effect",
					row.field, row.a, row.field, row.b, withA)
			case row.inert != "" && differs:
				t.Errorf("%s now has an effect (%q -> %s, %q -> %s); delete its inert mark (%s)",
					row.field, row.a, withA, row.b, withB, row.inert)
			}
		})
	}
}

// globalBuild numbers the builds, so each is its own route and client.
var globalBuild atomic.Int64

// observeGlobal builds a route's chain under a global config with the field
// set to value, and records what one probe from a fresh client gets back.
func observeGlobal(t *testing.T, row globalEffect, value string, rowIndex int) string {
	t.Helper()
	n := globalBuild.Add(1)
	// Reputation belongs to a /24, so each build's client is on its own.
	peer := fmt.Sprintf("100.%d.%d.7", 80+rowIndex, n%250)
	cfg := &gateonv1.GlobalConfig{SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{}}
	row.set(cfg, value)
	if row.setup != nil {
		row.setup(t, peer, cfg)
	}
	store := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	if err := store.Update(t.Context(), cfg); err != nil {
		t.Fatalf("store global config: %v", err)
	}
	rt := &gateonv1.Route{Id: fmt.Sprintf("global-effect-%d", n), Name: "global-effect", Type: "http"}
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := ApplyRouteMiddlewares(backend, rt, nil, &stubMiddlewareStore{}, store, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
	req.RemoteAddr = peer + ":4444"
	req.Header.Set("User-Agent", "global-effect-test")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := strconv.Itoa(rec.Code)
	if row.header != "" {
		out += " " + row.header + "=" + rec.Header().Get(row.header)
	}
	return out
}

func powConfig(c *gateonv1.GlobalConfig) *gateonv1.PowConfig {
	if c.SecurityAdvanced.Pow == nil {
		c.SecurityAdvanced.Pow = &gateonv1.PowConfig{Enabled: true, Difficulty: 1, ScoreThreshold: 5, Secret: effectPowSecret}
	}
	return c.SecurityAdvanced.Pow
}

// penalise lowers the probe client's reputation by penalty, so its threat
// score is penalty, and restores it afterwards.
func penalise(penalty float64) func(t *testing.T, peer string, _ *gateonv1.GlobalConfig) {
	return func(t *testing.T, peer string, _ *gateonv1.GlobalConfig) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
		r.RemoteAddr = peer + ":4444"
		r.Header.Set("User-Agent", "global-effect-test")
		id := telemetry.GetReputationID(r)
		telemetry.DecreaseReputation(id, penalty, "test: global setting effect")
		t.Cleanup(func() { telemetry.ResetReputation(id) })
		if got := 100 - telemetry.GetReputationScore(id); got != penalty {
			t.Fatalf("threat score %v, want %v; the row would prove nothing", got, penalty)
		}
	}
}

// listInFeed publishes a feed store built from the config the row set, the
// way the gateway builds it, with the probe client listed at score.
func listInFeed(score float64) func(t *testing.T, peer string, c *gateonv1.GlobalConfig) {
	return func(t *testing.T, peer string, c *gateonv1.GlobalConfig) {
		t.Helper()
		s := reputation.NewIPReputationStore(c.GetSecurityAdvanced().GetIpReputation())
		s.SetIPScore(peer, score)
		reputation.Publish(s)
		t.Cleanup(func() { reputation.Publish(nil) })
	}
}

func mustFloat(v string) float64 {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		panic(err)
	}
	return f
}
