// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oversizedJSON is a syntactically valid provider answer whose leading
// padding field alone exceeds the response ceiling. Unknown fields are
// ignored by encoding/json, so without a ceiling every client decodes it and
// returns a score; with one, the stream is cut inside the padding and the
// decode fails -- which is the only outcome that bounds memory.
func oversizedJSON(tail string) string {
	return `{"pad":"` + strings.Repeat("x", externalResponseMaxBytes+1024) + `",` + tail + `}`
}

// TestProviderResponsesAreBounded: the provider timeout bounds how long a
// lookup may take, not how much it may read; a provider that keeps sending
// was decoded into memory for the whole of those ten seconds.
//
// Root cause: the three CheckIP decoders read resp.Body with no LimitReader.
func TestProviderResponsesAreBounded(t *testing.T) {
	type provider struct {
		name  string
		small string // a real-shaped answer that must still decode
		check func(baseURL string) (int, error)
	}
	providers := []provider{
		{
			name:  "AbuseIPDB",
			small: `{"data":{"abuseConfidenceScore":77}}`,
			check: func(u string) (int, error) {
				c := NewAbuseIPDBClient("k")
				c.BaseURL = u
				return c.CheckIP(context.Background(), "203.0.113.9")
			},
		},
		{
			name:  "VirusTotal",
			small: `{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"harmless":5}}}}`,
			check: func(u string) (int, error) {
				c := NewVirusTotalClient("k")
				c.BaseURL = u + "/"
				return c.CheckIP(context.Background(), "203.0.113.9")
			},
		},
		{
			name:  "AlienVault",
			small: `{"pulse_info":{"count":3}}`,
			check: func(u string) (int, error) {
				c := NewAlienVaultClient("k")
				c.BaseURL = u + "/"
				return c.CheckIP(context.Background(), "203.0.113.9")
			},
		},
	}

	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			t.Run("oversized answer is refused, not decoded", func(t *testing.T) {
				body := oversizedJSON(strings.TrimSuffix(strings.TrimPrefix(p.small, "{"), "}"))
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(body))
				}))
				defer srv.Close()

				if score, err := p.check(srv.URL); err == nil {
					t.Fatalf("a %d-byte provider answer was decoded in full (score %d); "+
						"the response read is unbounded", len(body), score)
				}
			})

			t.Run("real-sized answer still decodes", func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(p.small))
				}))
				defer srv.Close()

				if _, err := p.check(srv.URL); err != nil {
					t.Fatalf("a real-sized answer was refused: %v -- the bound must only "+
						"cut off answers that are actually oversized", err)
				}
			})
		})
	}
}
