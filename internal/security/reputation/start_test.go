// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestStartWithoutAnUpdateInterval is the regression test for a boot-time
// crash.
//
// Start built its ticker from UpdateIntervalHours before checking whether that
// was zero, and time.NewTicker panics on a non-positive interval. Zero is the
// default: the stock global config carries an empty IPReputationConfig, and the
// dashboard's interval field is optional. So an operator who switched IP
// reputation on and saved got a gateway that worked until its next restart and
// then panicked in main on every start after it.
//
// The existing tests called update directly and never Start, which is the only
// reason this was not caught.
func TestStartWithoutAnUpdateInterval(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "203.0.113.50")
	}))
	t.Cleanup(feed.Close)

	for _, hours := range []int32{0, -1} {
		t.Run(fmt.Sprintf("interval %dh", hours), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			store := NewIPReputationStore(&gateonv1.IPReputationConfig{
				Enabled:             true,
				FeedUrls:            []string{feed.URL},
				UpdateIntervalHours: hours,
			})
			store.Start(ctx)

			if bad, _ := store.IsBad("203.0.113.50"); !bad {
				t.Fatal("Start returned without loading the feed")
			}
		})
	}
}
