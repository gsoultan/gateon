// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// OPEN: with no MaxMind licence key -- the default, so no local GeoIP database
// -- every finding's geo lookup falls back to http://ip-api.com, in plaintext, one
// request per uncached client address, spaced a second apart. The unlisted-route
// detector has no config gate, so this runs on every analysis pass of a default
// install. Removing the fallback empties the dashboard's map for installs
// without a database, so it is a product decision.
// Run with: go test -tags openfinding -run GeoEnrichment ./internal/api/

// TestGeoEnrichmentKeepsClientAddressesLocal: five internet clients each ask
// for a path no route serves -- ordinary background scanning.
func TestGeoEnrichmentKeepsClientAddressesLocal(t *testing.T) {
	rec := &recordingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = prev })

	data := &DiagnosticData{}
	for i := range 5 {
		ip := fmt.Sprintf("203.0.113.%d", 150+i)
		data.Traces = append(data.Traces, &telemetry.TraceRecord{
			SourceIP: ip, Path: "/wp-admin/setup-config.php", Method: "GET", Status: "404",
			Timestamp: time.Now().Add(-time.Minute), UserAgent: "Mozilla/5.0",
		})
	}
	start := time.Now()
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	elapsed := time.Since(start)

	if urls := rec.urls(); len(urls) > 0 {
		t.Errorf("one analysis pass sent %d client addresses off the host (%s ...) and took %s",
			len(urls), urls[0], elapsed.Round(100*time.Millisecond))
	}
}

// recordingTransport answers every request as ip-api.com would and records
// what was asked.
type recordingTransport struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.URL.String())
	r.mu.Unlock()
	body := `{"status":"success","countryCode":"US","city":"Ashburn","lat":39.0,"lon":-77.5}`
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: req,
	}, nil
}

func (r *recordingTransport) urls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}
