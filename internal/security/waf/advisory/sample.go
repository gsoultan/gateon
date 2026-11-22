// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/redact"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// Why a request was offered. The worker is told, because "the gateway's own
// rules matched this and let it through" and "nothing matched this" are
// different questions.
const (
	WhyMatched       = "matched"
	WhyOutsideSchema = "outside_schema"
	WhySampled       = "sampled"
)

// maxRules is how many matched rule numbers a sample names.
const maxRules = 16

// Sample is one request as the worker is shown it: the tuning sample's entry
// (corpus.Capture, so no body, no credential, no client address) with a
// number to answer by and the reason it was sent.
type Sample struct {
	ID    string   `json:"id"`
	Why   string   `json:"why"`
	Rules []uint32 `json:"rules,omitempty"`
	*corpus.Entry

	// Source stays on the gateway. It is how a verdict finds its way back
	// to a client the worker was never told about.
	Source Source `json:"-"`
}

// Source is who sent a sampled request, kept beside the sample and never
// sent with it.
type Source struct {
	Addr        string
	Fingerprint string
	JA4, JA4H   string
	UserAgent   string
	Route       string
	URI         string
}

// Capture builds the sample for r, and reports false when r is not one to
// send: it does not fit the tuning sample's bounds, and a truncated request
// is one the client never sent.
//
// It copies what it keeps. The request is the proxy's to rewrite as soon as
// this returns, and the sample outlives it by however long the worker takes.
func Capture(r *http.Request, route, why string, rules []uint32) (*Sample, bool) {
	entry, ok := corpus.Capture(r, route)
	if !ok {
		return nil, false
	}
	if len(rules) > maxRules {
		rules = rules[:maxRules]
	}
	s := &Sample{Why: why, Rules: rules, Entry: entry}
	s.Source = Source{
		Addr:      request.ClientAddr(r),
		UserAgent: r.Header.Get("User-Agent"),
		Route:     route,
		URI:       redact.URI(r.RequestURI),
	}
	if rs := request.GetRequestState(r); rs != nil {
		s.Source.JA4, s.Source.JA4H, s.Source.Fingerprint = rs.JA4, rs.JA4H, rs.JA4Plus
	}
	return s, true
}
