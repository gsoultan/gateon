// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"context"
	"sync"
	"testing"
	"time"

	dservice "github.com/gsoultan/gateon/internal/domain/service"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// runCanary shifts a service's traffic weights over minutes on a detached
// goroutine. Only snapshotService was covered; the rollout loop itself was not.

type fakeSvcService struct {
	dservice.Service
	mu    sync.Mutex
	svc   *gateonv1.Service
	saves int
}

func (f *fakeSvcService) GetService(context.Context, string) (*gateonv1.Service, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.svc, f.svc != nil
}

func (f *fakeSvcService) SaveService(_ context.Context, svc *gateonv1.Service) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.svc = svc
	f.saves++
	return nil
}

func (f *fakeSvcService) saveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

type quietLogger struct{}

func (quietLogger) LogDebug(string, ...any) {}
func (quietLogger) LogInfo(string, ...any)  {}
func (quietLogger) LogWarn(string, ...any)  {}
func (quietLogger) LogError(string, ...any) {}

func canaryService(svc *gateonv1.Service) (*serviceImpl, *fakeSvcService) {
	f := &fakeSvcService{svc: svc}
	return &serviceImpl{svcService: f, logger: quietLogger{}, lifetime: context.Background()}, f
}

// TestRunCanaryStopsWhenItsContextIsCancelled is the shutdown property
// StartCanary claims and did not have.
//
// StartCanary detaches the rollout onto cs.lifetime rather than the request
// context, and says so: "hung off the process lifetime so it does stop at
// shutdown". It did not. The loop's only wait is time.Sleep(interval), which no
// cancellation interrupts, so a rollout configured to move over an hour sat in
// an uninterruptible sleep of several minutes per step while the process was
// trying to drain -- and then wrote another weight change on its way out.
//
// The interval here is two seconds and the context is already cancelled, so a
// loop that honours it returns immediately and one that does not takes at least
// two.
func TestRunCanaryStopsWhenItsContextIsCancelled(t *testing.T) {
	cs, fake := canaryService(&gateonv1.Service{
		Id:              "svc-1",
		WeightedTargets: []*gateonv1.Target{{Url: "http://v1", Weight: 100}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cs.runCanary(ctx, &gateonv1.StartCanaryRequest{
			ServiceId:       "svc-1",
			DurationMinutes: 1,
			Steps:           30, // 2s per step
			TargetWeights:   []*gateonv1.Target{{Url: "http://v1", Weight: 0}},
		})
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runCanary did not return on a cancelled context within 500ms.\n" +
			"Its only wait is time.Sleep, which cancellation cannot interrupt, so " +
			"a rollout keeps sleeping through shutdown and writes another weight " +
			"change on the way out. StartCanary's comment says this stops at " +
			"shutdown; nothing made that true.")
	}

	if n := fake.saveCount(); n != 0 {
		t.Errorf("it wrote %d weight changes after its context was cancelled", n)
	}
}

// TestRunCanaryBoundsTheStepCount covers the other end of the same loop.
//
// Steps arrives from the request and is only checked for being positive. Nothing
// between POST /v1/services/canary and here validates it, so Steps=1000000 with
// DurationMinutes=1 gives a sixty-nanosecond interval and a million rounds of
// SaveService -- each one a config write to disk and a route-chain invalidation.
// One API call, and the gateway spends itself rewriting its own configuration.
func TestRunCanaryBoundsTheStepCount(t *testing.T) {
	cs, fake := canaryService(&gateonv1.Service{
		Id:              "svc-1",
		WeightedTargets: []*gateonv1.Target{{Url: "http://v1", Weight: 100}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cs.runCanary(ctx, &gateonv1.StartCanaryRequest{
			ServiceId:       "svc-1",
			DurationMinutes: 1,
			Steps:           1000000,
			TargetWeights:   []*gateonv1.Target{{Url: "http://v1", Weight: 0}},
		})
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runCanary was still going after 3s")
	}

	// With a sane floor on the interval, a two-second window cannot produce
	// thousands of writes.
	if n := fake.saveCount(); n > 100 {
		t.Errorf("it performed %d service writes in under two seconds.\n"+
			"Steps is caller-supplied and only checked for being positive, so the "+
			"interval collapses to nanoseconds and every round writes the config "+
			"to disk and invalidates route chains. Bound the step count, or the "+
			"interval, or both.", n)
	}
}

// TestRunCanaryInterpolatesWeights is the control: the two checks above must not
// be satisfied by a loop that simply stopped working.
//
// It asserts progress rather than completion. DurationMinutes is measured in
// minutes and the interval now has a one-second floor, so a finished rollout
// takes at least a minute -- too long to run here. Two steps is enough to show
// the weights are being interpolated in the right direction.
func TestRunCanaryInterpolatesWeights(t *testing.T) {
	cs, fake := canaryService(&gateonv1.Service{
		Id: "svc-1",
		WeightedTargets: []*gateonv1.Target{
			{Url: "http://v1", Weight: 100},
			{Url: "http://v2", Weight: 0},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	cs.runCanary(ctx, &gateonv1.StartCanaryRequest{
		ServiceId:       "svc-1",
		DurationMinutes: 1,
		Steps:           60, // one second per step
		TargetWeights: []*gateonv1.Target{
			{Url: "http://v1", Weight: 0},
			{Url: "http://v2", Weight: 100},
		},
	})

	if fake.saveCount() == 0 {
		t.Fatal("no weights were written; the rollout did nothing, and the " +
			"cancellation and bounding tests above would pass against exactly that")
	}

	current, _ := fake.GetService(context.Background(), "svc-1")
	for _, tgt := range current.WeightedTargets {
		switch tgt.Url {
		case "http://v1":
			if tgt.Weight >= 100 || tgt.Weight < 0 {
				t.Errorf("v1 is at %d after two steps, want it moving down from 100 "+
					"towards 0", tgt.Weight)
			}
		case "http://v2":
			if tgt.Weight <= 0 || tgt.Weight > 100 {
				t.Errorf("v2 is at %d after two steps, want it moving up from 0 "+
					"towards 100", tgt.Weight)
			}
		}
	}
}
