// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestAHungModelDoesNotHoldUpResponses: the predictive balancer asks the
// model about a backend on every response it records, holding that backend's
// lock, and the model ran under its own lock with no deadline. A custom model
// that never returned stalled the response that asked, then every response
// from that backend behind the first lock, then every response from every
// backend behind the second.
func TestAHungModelDoesNotHoldUpResponses(t *testing.T) {
	p, err := loadModel(t, wasmModel(modelSpec{start: "_initialize", hangs: true, initSets: 0.25}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s := NewPredictorStrategy()
	s.SetPredictor(p)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, url := range []string{"http://a", "http://b"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 4 { // the third sample asks the model about three
					s.RecordLatency(url, 0.05)
				}
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("recording a response waited on a model that never answers")
	}
	if _, ok := s.Estimate("http://a", time.Now()); !ok {
		t.Error("the backend has no estimate: its samples were dropped rather than priced without the model")
	}
}

// TestAModelStoppedForOverrunningIsRestarted: a model stopped by its deadline
// answers nothing until restartCooldown has passed, then is started afresh --
// one slow answer must not switch a custom model off for the life of the
// process.
func TestAModelStoppedForOverrunningIsRestarted(t *testing.T) {
	p, err := loadModel(t, wasmModel(modelSpec{start: "_initialize", hangs: true, initSets: 0.25}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	clock := time.Unix(1_000_000, 0)
	p.now = func() time.Time { return clock }
	ctx := context.Background()

	if _, err := p.Predict(ctx, []float64{1, 2, 3}); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("overrunning prediction: err %v, want ErrModelUnavailable", err)
	}
	clock = clock.Add(restartCooldown - time.Second)
	if _, err := p.Predict(ctx, []float64{1, 2}); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("inside the cooldown: err %v, want ErrModelUnavailable", err)
	}
	clock = clock.Add(2 * time.Second)
	// The first prediction after the cooldown starts the restart in the
	// background and is refused; a later one is answered by the new instance.
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := p.Predict(ctx, []float64{1, 2})
		if err == nil {
			if got != 0.25 {
				t.Fatalf("restarted model answered %v, want 0.25", got)
			}
			return
		}
		if !errors.Is(err, ErrModelUnavailable) || time.Now().After(deadline) {
			t.Fatalf("after the cooldown: err %v; want an answer from a restarted model", err)
		}
		runtime.Gosched()
	}
}
