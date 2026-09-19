// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestWatchForwarderStopsWhenClientIsGone covers the goroutine behind every
// /v1/watch connection.
//
// It forwards audit, threat and metrics events into a 20-slot channel that the
// handler's write loop drains. That loop returns the moment the request context
// is cancelled -- the client closed the tab, the connection dropped -- and
// nothing drains the channel after that. A forward that was blocked on a full
// channel at that moment blocked forever: a slow client that let twenty events
// pile up and then disconnected leaked the goroutine and every buffered event,
// and each such connection leaked another. Any authenticated dashboard user can
// open and drop as many of these as they like.
//
// An unbuffered channel that nobody reads is that full buffer with the timing
// removed: the very first forward blocks, and the only way out is to notice the
// context.
func TestWatchForwarderStopsWhenClientIsGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone

	unread := make(chan WatchEvent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardWatchEvents(ctx, watchSources{initial: &telemetry.MetricsSnapshot{}}, unread)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder is still blocked sending to a channel nobody reads after its client left; " +
			"the goroutine and its buffered events leak for every dropped /v1/watch connection")
	}
}
