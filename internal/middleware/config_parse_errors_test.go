// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Middleware config arrives as map[string]string from the dashboard, and every
// numeric field was parsed with the error discarded. A typo therefore produced
// the zero value silently -- and for several of these, zero means the
// protection is off:
//
//	max_depth / max_complexity  0 means "no limit" (serveGraphQLFirewall)
//	sts_seconds                 0 means no Strict-Transport-Security header
//
// The dashboard goes on showing what the operator typed either way. Factory
// .Validate is what the dashboard calls before saving, so returning the error
// makes a typo visible at the moment it is made rather than never.
func TestFactoryRejectsMalformedNumericConfig(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	cases := []struct {
		name   string
		mwType string
		cfg    map[string]string
		badKey string
	}{
		{"graphql max_depth", "graphql_firewall", map[string]string{"max_depth": "ten"}, "max_depth"},
		{"graphql max_complexity", "graphql_firewall", map[string]string{"max_complexity": "1_000"}, "max_complexity"},
		{"hsts seconds", "headers", map[string]string{"sts_seconds": "31536000s"}, "sts_seconds"},
		{"cors max_age", "cors", map[string]string{"max_age": "1 hour"}, "max_age"},
		{"retry attempts", "retry", map[string]string{"attempts": "three"}, "attempts"},
		{"pow difficulty", "pow", map[string]string{"difficulty": "hard"}, "difficulty"},
		{"tarpit base_delay", "tarpit", map[string]string{"base_delay": "5"}, "base_delay"},
		{"circuit breaker window", "circuit_breaker", map[string]string{"window_size": "1min"}, "window_size"},
		{"inflight amount", "inflightreq", map[string]string{"amount": "lots"}, "amount"},
		{"ratelimit rpm", "ratelimit", map[string]string{"requests_per_minute": "60/min"}, "requests_per_minute"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Validate(&gateonv1.Middleware{Type: tc.mwType, Config: tc.cfg})
			if err == nil {
				t.Fatalf("a malformed %q was accepted; the value silently becomes 0 "+
					"while the dashboard shows what was typed", tc.badKey)
			}
			// The message has to name the key, or an operator with twenty
			// settings learns only that one of them is wrong.
			if !strings.Contains(err.Error(), tc.badKey) {
				t.Errorf("error does not name the offending key %q: %v", tc.badKey, err)
			}
		})
	}
}

// TestFactoryAcceptsAbsentAndValidNumericConfig is the other half, and the
// reason the helpers distinguish absent from malformed: an unset key means the
// operator did not configure this, so the default is correct and silent.
func TestFactoryAcceptsAbsentAndValidNumericConfig(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	cases := []struct {
		name   string
		mwType string
		cfg    map[string]string
	}{
		{"graphql absent", "graphql_firewall", map[string]string{}},
		{"graphql valid", "graphql_firewall", map[string]string{"max_depth": "10", "max_complexity": "500"}},
		{"headers absent", "headers", map[string]string{}},
		{"headers valid", "headers", map[string]string{"sts_seconds": "31536000"}},
		{"cors valid", "cors", map[string]string{"max_age": "3600"}},
		{"retry valid", "retry", map[string]string{"attempts": "3"}},
		{"tarpit valid", "tarpit", map[string]string{"base_delay": "5s", "max_delay": "30s", "threshold": "0.5"}},
		{"circuit breaker valid", "circuit_breaker", map[string]string{"window_size": "1m", "sleep_window": "30s", "error_threshold": "0.5", "min_requests": "20"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.Validate(&gateonv1.Middleware{Type: tc.mwType, Config: tc.cfg}); err != nil {
				t.Errorf("a config that is absent or valid was rejected: %v", err)
			}
		})
	}
}
