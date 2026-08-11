// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"
)

// Work that must outlive the RPC that started it — a multi-minute ClamAV
// install, a full scan — used to be spawned on context.Background(). That
// solved the wrong half of the problem: it is correctly detached from the
// request, but it is also detached from the gateway, so nothing could stop it
// at shutdown and nothing could observe it. The process-lifetime context keeps
// the first property and restores the second.
//
// Against the pre-fix code these goroutines took context.Background(), which is
// never Done, so the cancellation assertion below could not hold.

func TestDetachedUsesLifetimeWhenSet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ApiService{Lifetime: ctx}

	got := s.detached()
	if got.Err() != nil {
		t.Fatalf("detached() already cancelled before shutdown: %v", got.Err())
	}

	// Shutting the gateway down must reach the detached work.
	cancel()
	if got.Err() == nil {
		t.Error("detached() context did not observe shutdown; " +
			"background work would keep running with nothing able to stop it")
	}
	if !ctxIsDone(got) {
		t.Error("detached() context Done channel never closed")
	}
}

// A bare ApiService literal is how the tests across this repo build one, so the
// accessor has to tolerate an unset Lifetime rather than panic.
func TestDetachedFallsBackToBackground(t *testing.T) {
	s := &ApiService{}

	got := s.detached()
	if got == nil {
		t.Fatal("detached() returned nil; callers pass this straight to exec")
	}
	if err := got.Err(); err != nil {
		t.Errorf("fallback context is already cancelled: %v", err)
	}
}

// TestDetachedIsNotTheRequestContext guards the property that makes this
// correct: cancelling a request must not cancel the detached work, or a
// multi-minute install would die the moment its RPC returned.
func TestDetachedIsNotTheRequestContext(t *testing.T) {
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	s := &ApiService{Lifetime: lifetime}

	reqCtx, cancelReq := context.WithCancel(context.Background())
	detached := s.detached()

	// The RPC returns and its context is cancelled.
	cancelReq()
	<-reqCtx.Done()

	if detached.Err() != nil {
		t.Error("detached work was cancelled when the request ended; " +
			"a multi-minute install would not survive its own RPC")
	}
}

func ctxIsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
