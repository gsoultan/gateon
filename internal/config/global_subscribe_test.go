package config

import (
	"path/filepath"
	"sync"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func newTestRegistry(t *testing.T) *GlobalRegistry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "global.json")
	return NewGlobalRegistry(path)
}

func TestGlobalRegistry_SubscribeNotifiesOnUpdate(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := t.Context()

	var (
		mu     sync.Mutex
		gotOld *gateonv1.GlobalConfig
		gotNew *gateonv1.GlobalConfig
		calls  int
	)
	reg.Subscribe(func(oldCfg, newCfg *gateonv1.GlobalConfig) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		gotOld, gotNew = oldCfg, newCfg
	})

	next := &gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true},
	}
	if err := reg.Update(ctx, next); err != nil {
		t.Fatalf("Update: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("listener calls = %d; want 1", calls)
	}
	if gotOld == nil {
		t.Fatalf("old config not delivered")
	}
	if !gotNew.GetAnomalyDetection().GetEnabled() {
		t.Fatalf("new config not delivered with expected value")
	}
}

func TestGlobalRegistry_SubscribeOrderAndMultiple(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := t.Context()

	var order []int
	for i := range 3 {
		reg.Subscribe(func(_, _ *gateonv1.GlobalConfig) {
			order = append(order, i)
		})
	}
	if err := reg.Update(ctx, &gateonv1.GlobalConfig{}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	want := []int{0, 1, 2}
	if len(order) != len(want) {
		t.Fatalf("listener order = %v; want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("listener order = %v; want %v", order, want)
		}
	}
}

func TestGlobalRegistry_SubscribeNilIgnored(t *testing.T) {
	reg := newTestRegistry(t)
	reg.Subscribe(nil) // must not panic or register anything
	if err := reg.Update(t.Context(), &gateonv1.GlobalConfig{}); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestGlobalRegistry_ListenerReceivesClone(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := t.Context()

	reg.Subscribe(func(_, newCfg *gateonv1.GlobalConfig) {
		// Mutating the delivered clone must not affect live registry state.
		if newCfg.GetAnomalyDetection() != nil {
			newCfg.AnomalyDetection.Enabled = false
		}
	})

	next := &gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true},
	}
	if err := reg.Update(ctx, next); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !reg.Get(ctx).GetAnomalyDetection().GetEnabled() {
		t.Fatalf("listener mutated live config via clone")
	}
}
