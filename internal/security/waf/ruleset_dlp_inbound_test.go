// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"testing"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// inboundSpecs returns the request-phase data-leak rules.
func inboundSpecs() []spec {
	var out []spec
	for _, s := range defaultSpecs {
		for _, tag := range s.tags {
			if tag == TagDlpInbound {
				out = append(out, s)
			}
		}
	}
	return out
}

// TestInboundDLPRulesNeverBlock is the property the whole direction depends on.
// Refusing a POST because it contains a secret throws away what the user typed
// and teaches them to route around the gateway — which leaves the organisation
// worse off than before, because now nobody can see the secret at all.
func TestInboundDLPRulesNeverBlock(t *testing.T) {
	t.Parallel()

	specs := inboundSpecs()
	if len(specs) == 0 {
		t.Fatal("no inbound data-leak rules in the corpus")
	}
	for _, s := range specs {
		if s.action == nil {
			t.Errorf("rule %d has no action override, so it blocks", s.id)
			continue
		}
		if s.action != rules.Log {
			t.Errorf("rule %d acts with %v, want log", s.id, s.action)
		}
		if s.status != 0 {
			t.Errorf("rule %d sets status %d; a logging rule has no status", s.id, s.status)
		}
		if s.phase != types.PhaseRequestBody {
			t.Errorf("rule %d runs at %v, want the request-body phase", s.id, s.phase)
		}
	}
}

// TestNoInboundCardOrSSNRule pins the asymmetry that justifies a separate rule
// set. Outbound a card number is a leak; inbound it is a customer paying for
// something, and a checkout form is the single most expensive place for a WAF
// to be wrong.
func TestNoInboundCardOrSSNRule(t *testing.T) {
	t.Parallel()

	card := NewCardNumber()
	for _, s := range inboundSpecs() {
		if _, isCard := s.op.(*CardNumber); isCard {
			t.Errorf("rule %d puts a card detector on the request path", s.id)
		}
		// The SSN detector is a bare regex, so it is identified by behaviour:
		// anything matching a plain SSN inbound would block checkout-adjacent
		// forms for the same reason.
		if _, ok := s.op.Eval(nil, []byte("123-45-6789")); ok {
			t.Errorf("rule %d matches a bare SSN on the request path", s.id)
		}
		if _, ok := s.op.Eval(nil, []byte("4111111111111111")); ok && s.op != card {
			t.Errorf("rule %d matches a bare card number on the request path", s.id)
		}
	}
}

// TestInboundDLPDetectsSecrets checks the direction actually works, using the
// same fixtures the response-phase tests use.
func TestInboundDLPDetectsSecrets(t *testing.T) {
	t.Parallel()

	specs := inboundSpecs()
	findsIt := func(payload string) bool {
		for _, s := range specs {
			if _, ok := s.op.Eval(nil, []byte(payload)); ok {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct{ name, payload string }{
		{"aws key in a ticket", "here is the key AKIAIOSFODNN7EXAMPLE, please try it"},
		{"private key attached", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."},
		{"stripe key in a form", fakeStripeLive},
		{"connection string", "postgres://app:s3cr3t@db.internal:5432/prod"},
		{"service account json", `{"type": "service_account", "project_id": "prod"}`},
		{"slack webhook", "https://hooks.slack.com/services/T00/B00/XXXX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !findsIt(tc.payload) {
				t.Errorf("no inbound rule caught %q", tc.payload)
			}
		})
	}

	// And the traffic that must stay quiet.
	for _, tc := range []struct{ name, payload string }{
		{"a card number at checkout", `{"card":"4111111111111111","cvv":"123"}`},
		{"a social security number", `{"ssn":"123-45-6789"}`},
		{"ordinary prose", "please reset my password, my order is 4000123400001234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if findsIt(tc.payload) {
				t.Errorf("an inbound rule fired on ordinary traffic: %q", tc.payload)
			}
		})
	}
}

// TestInboundDLPIsSeparatelyDisableable checks the two directions can be turned
// off independently, since an operator may well want one and not the other.
func TestInboundDLPIsSeparatelyDisableable(t *testing.T) {
	t.Parallel()

	base := Policy{ParanoiaLevel: 2, ResponseInspection: true}
	full := base.Ruleset()

	noInbound := base
	noInbound.DisabledTags = map[string]bool{TagDlpInbound: true}
	got := noInbound.Ruleset()
	if len(got) >= len(full) {
		t.Errorf("disabling %q changed nothing: %d of %d", TagDlpInbound, len(got), len(full))
	}
	for _, r := range got {
		for _, tag := range r.Tags {
			if tag == TagDlpInbound {
				t.Errorf("rule %d survived %q being disabled", r.ID, TagDlpInbound)
			}
		}
	}
	// The response half must survive: the tags are independent.
	var responseDLP int
	for _, r := range got {
		if r.Phase == types.PhaseResponseBody {
			for _, tag := range r.Tags {
				if tag == TagDlp {
					responseDLP++
				}
			}
		}
	}
	if responseDLP == 0 {
		t.Error("disabling the inbound tag also removed the response-phase rules")
	}
}

// TestExistingRulesStillBlock guards the refactor that made a non-blocking
// action expressible. A corpus where a rule quietly stopped refusing anything
// would be the worst possible outcome of adding the field.
func TestExistingRulesStillBlock(t *testing.T) {
	t.Parallel()

	for _, s := range defaultSpecs {
		inbound := false
		for _, tag := range s.tags {
			if tag == TagDlpInbound {
				inbound = true
			}
		}
		if inbound {
			continue
		}
		if s.action != nil {
			t.Errorf("rule %d has a non-default action but is not an inbound rule", s.id)
		}
	}
}
