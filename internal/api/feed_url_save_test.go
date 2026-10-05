// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func withFeeds(urls ...string) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
		IpReputation: &gateonv1.IPReputationConfig{Enabled: true, FeedUrls: urls},
	}}
}

// TestASavedFeedMustBeHTTPS is TRUTH-NEW-4's save half: a feed decides whom
// every entrypoint refuses, and an http:// feed saved with success let anyone
// on the path between the gateway and the feed's host rewrite that list. A
// new http:// feed off loopback is refused at save, the path REST, Connect
// and gRPC share; https:// and a loopback mirror save; a feed already stored
// is not judged again, so it does not hold unrelated saves hostage.
func TestASavedFeedMustBeHTTPS(t *testing.T) {
	stored := withFeeds("http://legacy.example.com/drop.txt")
	err := validateGlobalSave(stored, withFeeds("http://legacy.example.com/drop.txt", "http://feeds.example.com/new.txt"))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a new http:// feed saved: %v", err)
	}
	for _, ok := range [][]string{
		{"https://feeds.example.com/drop.txt"},
		{"http://127.0.0.1:8082/feed.txt"},
		{"http://legacy.example.com/drop.txt"},
	} {
		if err := validateGlobalSave(stored, withFeeds(ok...)); err != nil {
			t.Errorf("feeds %v refused at save: %v", ok, err)
		}
	}
}
