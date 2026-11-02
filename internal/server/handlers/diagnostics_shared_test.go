// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Every diagnostics stream computed its own snapshot on every tick. Streams
// that tick inside one period now share one computation: twenty streams
// ticking together, and again inside the period, compute it once.
func TestDiagnosticsStreamsShareOneComputation(t *testing.T) {
	var computed atomic.Int32
	shared := newSharedDiagnostics(func(context.Context, *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error) {
		computed.Add(1)
		time.Sleep(50 * time.Millisecond) // long enough for every stream to arrive while it runs
		return &gateonv1.GetDiagnosticsResponse{}, nil
	})
	const streams = 20
	var wg sync.WaitGroup
	for range streams {
		wg.Go(func() {
			for range 3 {
				if _, err := shared.get(context.Background()); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if n := computed.Load(); n != 1 {
		t.Fatalf("%d streams ticking three times each computed diagnostics %d times, want 1", streams, n)
	}
}

// A stream that ends while the shared computation runs does not take the
// computation down with it: the others still get the result.
func TestAStreamEndingDoesNotCancelTheSharedRead(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	shared := newSharedDiagnostics(func(ctx context.Context, _ *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error) {
		close(started)
		select {
		case <-release:
			return &gateonv1.GetDiagnosticsResponse{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	first, cancelFirst := context.WithCancel(context.Background())
	go func() { _, _ = shared.get(first) }()
	<-started
	cancelFirst()
	done := make(chan error, 1)
	go func() {
		_, err := shared.get(context.Background())
		done <- err
	}()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the second stream got %v after the first ended", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the second stream never got the shared result")
	}
}
