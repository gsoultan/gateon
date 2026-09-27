// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnalyzeConfigTLSInsightMatchesTheNegotiatedMinimum holds the TLS insight
// to what the gateway actually negotiates.
//
// The TLS manager reads min_tls_version through gtls.ParseTLSVersion, which
// accepts "TLS1.0", "TLS10", "TLS_1_0" and "tls 1.0" alike and falls back to
// TLS 1.2 when the setting is empty. The advisory tested the raw string for the
// substrings "1.0" and "1.1" and treated empty as weak, so it raised a critical
// finding on every install that had left the setting at its TLS 1.2 default,
// and said nothing when TLS 1.0 was spelled any way but one.
func TestAnalyzeConfigTLSInsightMatchesTheNegotiatedMinimum(t *testing.T) {
	cases := []struct {
		min  string
		weak bool
	}{
		{min: "", weak: false}, // unset: the manager negotiates TLS 1.2 at least
		{min: "TLS1.2", weak: false},
		{min: "TLS13", weak: false},
		{min: "TLS1.0", weak: true},
		{min: "TLS10", weak: true},
		{min: "TLS_1_1", weak: true},
		{min: "tls 1.1", weak: true},
	}
	for _, tc := range cases {
		cfg := &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{Enabled: true, MinTlsVersion: tc.min}}
		got := hasInsight(analyzeConfig(t.Context(), cfg), "Weak minimum TLS version")
		if got != tc.weak {
			t.Errorf("min_tls_version %q: weak-TLS insight reported = %v, want %v", tc.min, got, tc.weak)
		}
	}
}

// hasInsight reports whether any insight's title starts with prefix.
func hasInsight(resp aiAnalysisResponse, prefix string) bool {
	for _, in := range resp.Insights {
		if strings.HasPrefix(in.Title, prefix) {
			return true
		}
	}
	return false
}
