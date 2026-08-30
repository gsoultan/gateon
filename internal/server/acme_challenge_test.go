// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSupportedChallengeTypesAreCarriedThrough is the regression guard: the
// configured challenge was dropped on the way into the TLS manager, which read
// GATEON_ACME_CHALLENGE_TYPE alone, so setting it in the dashboard did nothing.
func TestSupportedChallengeTypesAreCarriedThrough(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http", "http"},
		{"tls-alpn", "tls-alpn"},
		{"HTTP", "http"},
		{"  tls-alpn  ", "tls-alpn"},
	} {
		if got := acmeChallengeType(tc.in); got != tc.want {
			t.Errorf("acmeChallengeType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// "dns" was listed as valid in the proto but cannot work: this build uses
// autocert, which implements HTTP-01 and TLS-ALPN-01 only. Forwarding it would
// leave the manager with a challenge it cannot run and issuance would fail with
// no explanation, so it falls back to the default instead.
func TestDNSChallengeFallsBackRatherThanBeingForwarded(t *testing.T) {
	if got := acmeChallengeType("dns"); got != "" {
		t.Fatalf("acmeChallengeType(\"dns\") = %q, want the empty default", got)
	}
	if got := acmeChallengeType("DNS"); got != "" {
		t.Fatalf("acmeChallengeType(\"DNS\") = %q, want the empty default", got)
	}
}

// Unset stays unset, so an install that configures nothing behaves as before.
func TestUnsetAndUnknownFallBackToTheDefault(t *testing.T) {
	for _, in := range []string{"", "   ", "dns-01", "wildcard", "nonsense"} {
		if got := acmeChallengeType(in); got != "" {
			t.Errorf("acmeChallengeType(%q) = %q, want the empty default", in, got)
		}
	}
}

// TestBuildGtlsConfigCarriesTheChallengeType guards the wiring, not the helper.
//
// Asserting on acmeChallengeType alone still passes if BuildGtlsConfig stops
// calling it, which is exactly the bug being fixed — the value has to be
// observed on the config the TLS manager actually receives.
func TestBuildGtlsConfigCarriesTheChallengeType(t *testing.T) {
	s := &Server{GlobalStore: &mockGlobalRegVerify{config: &gateonv1.GlobalConfig{
		Tls: &gateonv1.TlsConfig{
			Enabled: true,
			Acme:    &gateonv1.AcmeConfig{Enabled: true, Email: "ops@example.com", ChallengeType: "tls-alpn"},
		},
	}}}

	got := BuildGtlsConfig(s)
	if got.Acme.ChallengeType != "tls-alpn" {
		t.Fatalf("Acme.ChallengeType = %q, want the configured tls-alpn", got.Acme.ChallengeType)
	}
}

// An unsupported challenge must not reach the manager, which would fail
// issuance with nothing pointing at the cause.
func TestBuildGtlsConfigRefusesDNSChallenge(t *testing.T) {
	s := &Server{GlobalStore: &mockGlobalRegVerify{config: &gateonv1.GlobalConfig{
		Tls: &gateonv1.TlsConfig{
			Enabled: true,
			Acme:    &gateonv1.AcmeConfig{Enabled: true, Email: "ops@example.com", ChallengeType: "dns"},
		},
	}}}

	if got := BuildGtlsConfig(s).Acme.ChallengeType; got != "" {
		t.Fatalf("Acme.ChallengeType = %q, want dns to fall back to the default", got)
	}
}
