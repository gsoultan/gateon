// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
)

// refusingTransport records every outbound request and fails it.
type refusingTransport struct {
	mu   sync.Mutex
	seen []string
}

func (r *refusingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, req.URL.String())
	return nil, errors.New("no outbound requests in this test")
}

// TestGeoLookupsNeverLeaveTheHost: with no MaxMind database -- the default,
// since the database needs a licence key -- every client address the analysis
// looked up was sent in plaintext to http://ip-api.com, one request a second.
// Client addresses are personal data; a gateway must not ship them to a third
// party nobody configured. Without a local database the answer is "unknown".
func TestGeoLookupsNeverLeaveTheHost(t *testing.T) {
	rec := &refusingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = prev })

	geoMu.RLock()
	loaded := geoDB != nil
	geoMu.RUnlock()
	if loaded {
		t.Skip("a local GeoIP database is loaded in this process; the fallback is only taken without one")
	}

	for _, ip := range []string{"203.0.113.7", "2001:db8::7", "8.8.8.8"} {
		if country, _, _, _ := ResolveIPInfo(context.Background(), ip); country != "XX" {
			t.Errorf("ResolveIPInfo(%s) = %q without a local database, want XX (unknown)", ip, country)
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.seen) > 0 {
		t.Errorf("geo lookups sent %d client addresses off the host: %v", len(rec.seen), rec.seen)
	}
}
