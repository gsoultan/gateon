// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// publishFeed starts a feed server listing entries, loads it into a store the
// way the gateway does (Start), and publishes the store for the test.
func publishFeed(t *testing.T, threshold float64, entries ...string) {
	t.Helper()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for _, e := range entries {
			_, _ = fmt.Fprintln(w, e)
		}
	}))
	t.Cleanup(feed.Close)
	store := reputation.NewIPReputationStore(&gateonv1.IPReputationConfig{
		Enabled: true, FeedUrls: []string{feed.URL}, BlockThreshold: threshold,
	})
	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx)
	reputation.Publish(store)
	t.Cleanup(func() {
		reputation.Publish(nil)
		cancel()
		store.Wait()
	})
}

// TestAFeedListedAddressIsRefusedWithoutAWAF is truth T3: "IP Reputation --
// sync with threat feeds to block known malicious actors" loaded the feed and
// refused no one, because only a WAF rule behind the WAF's own, separate
// ip_reputation switch read it. With no WAF on the route a listed address was
// served (the review's /n/x answered 200 to 192.0.2.66). The feed is now
// enforced by the IP decision every entrypoint and route already makes.
func TestAFeedListedAddressIsRefusedWithoutAWAF(t *testing.T) {
	scopeTestStore(t)
	publishFeed(t, 0, "192.0.2.66", "198.51.100.0/24")

	for _, ip := range []string{"192.0.2.66", "198.51.100.9"} {
		if code := ipMitigationStatus(ip); code != http.StatusForbidden {
			t.Errorf("%s is listed by the feed and got %d, want 403", ip, code)
		}
		if !AddressBlocked(ip) {
			t.Errorf("AddressBlocked(%s) = false; a TCP entrypoint would accept it", ip)
		}
	}
	if code := ipMitigationStatus("192.0.2.67"); code != http.StatusOK {
		t.Errorf("an unlisted neighbour got %d, want 200", code)
	}
}

// TestAFeedListingHonoursTheExemptionAndTheThreshold pins the two limits the
// enforcement keeps: loopback and GATEON_MITIGATION_ALLOWLIST are never
// refused (mitigation.ExemptFromEnforcement, the rule every other IP block
// applies), and a threshold above the listing score loads the feed and refuses
// no one, as the dashboard's threshold field says.
func TestAFeedListingHonoursTheExemptionAndTheThreshold(t *testing.T) {
	scopeTestStore(t)
	const allowlisted = "203.0.113.180"
	publishFeed(t, 0, allowlisted, "127.0.0.1", "::1")
	withAllowlist(t, allowlisted+"/32")
	for _, ip := range []string{allowlisted, "127.0.0.1", "::1"} {
		if code := ipMitigationStatus(ip); code != http.StatusOK {
			t.Errorf("%s is listed but exempt from enforcement, and got %d, want 200", ip, code)
		}
	}

	publishFeed(t, 101, "192.0.2.70")
	if code := ipMitigationStatus("192.0.2.70"); code != http.StatusOK {
		t.Errorf("listed below a threshold of 101: got %d, want 200", code)
	}
}
