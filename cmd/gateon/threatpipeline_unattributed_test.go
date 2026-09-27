// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestAnUnattributedThreatIsNotCorrelated pins the last place a threat its
// source did not choose to send could be held against that source.
//
// The honeypot records a trap hit that another site's page made a visitor's
// browser send, and records it Unattributed so the store neither penalises nor
// escalates it. The correlation engine is the third consumer: an incident's
// response degrades every participating address's reputation and can shun it,
// so a correlated unattributed signal -- say, beside a WAF hit laundered
// through the same page -- would ban the visitor by a longer route.
func TestAnUnattributedThreatIsNotCorrelated(t *testing.T) {
	signals := make(chan correlation.Signal, 2)
	sinks := threatSinks{signals: signals, correlate: true}

	sinks.forward(&telemetry.SecurityThreat{
		Type: "honeypot_triggered", SourceIP: "198.51.100.199", Unattributed: true,
	})
	sinks.forward(&telemetry.SecurityThreat{Type: "honeypot_triggered", SourceIP: "203.0.113.251"})

	if got := len(signals); got != 1 {
		t.Fatalf("%d signals reached the correlation engine, want 1: the unattributed threat "+
			"was correlated, or the attributed one was not", got)
	}
	if s := <-signals; s.SourceIP != "203.0.113.251" {
		t.Errorf("the correlation engine got a signal from %s, the source of the unattributed threat", s.SourceIP)
	}
}
