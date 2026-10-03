// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestListedReadsThePublishedStoreAtItsThreshold pins the request-path
// predicate the entrypoints ask: nothing is listed until a store is
// published, a listing refuses at or above the configured threshold, and
// withdrawing the store withdraws the listings.
func TestListedReadsThePublishedStoreAtItsThreshold(t *testing.T) {
	t.Cleanup(func() { Publish(nil) })
	if Listed("192.0.2.66") {
		t.Fatal("listed with no store published")
	}

	store := NewIPReputationStore(&gateonv1.IPReputationConfig{Enabled: true})
	store.SetIPScore("192.0.2.66", feedListedScore)
	Publish(store)
	if !Listed("192.0.2.66") {
		t.Error("a feed listing at the default threshold is not listed")
	}
	if Listed("192.0.2.67") {
		t.Error("an unlisted address is listed")
	}

	store.Reconfigure(&gateonv1.IPReputationConfig{Enabled: true, BlockThreshold: feedListedScore + 1})
	store.SetIPScore("192.0.2.66", feedListedScore)
	if Listed("192.0.2.66") {
		t.Error("listed below the configured threshold")
	}

	Publish(nil)
	if Listed("192.0.2.66") {
		t.Error("still listed after the store was withdrawn")
	}
}

// TestWaitReturnsWhenStartNeverRan: Wait is a join, and with no loop there is
// nothing to join.
func TestWaitReturnsWhenStartNeverRan(t *testing.T) {
	NewIPReputationStore(nil).Wait()
}
