// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"os"
	"sort"
	"strings"

	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// What to do about a leak is a different question from whether there is one,
// and until now gateon only had one answer: refuse the whole response with a
// 403, or — if headers were already committed — cut it off mid-body.
//
// That is the right default and the wrong only option. A data-leak programme is
// usually rolled out in stages: watch first, then redact, then block once the
// false-positive rate is known. An organisation that cannot risk a 403 on a
// customer-facing page will not enable a control whose only setting is 403, so
// the strictest available action ends up being no action at all.
//
// Three actions, then, applying to data-leak findings only. An SQL injection is
// not made safe by redacting it, so nothing here touches the rest of the corpus.
type dlpAction uint8

const (
	// dlpBlock refuses the response. The default, and unchanged behaviour.
	dlpBlock dlpAction = iota
	// dlpRedact replaces each finding with a marker and forwards the rest.
	dlpRedact
	// dlpAudit records the finding and forwards the response untouched.
	dlpAudit
)

// dlpActionEnv is the environment path for the action, so a deployment can set
// it without a config write.
const dlpActionEnv = "GATEON_WAF_DLP_ACTION"

// String implements fmt.Stringer, and is what the config fingerprint hashes.
func (a dlpAction) String() string {
	switch a {
	case dlpRedact:
		return "redact"
	case dlpAudit:
		return "audit"
	default:
		return "block"
	}
}

// parseDLPAction reads the action from a config value, falling back to the
// environment and then to blocking.
//
// An unrecognised value is the interesting case: it resolves to block rather
// than to the most permissive setting, because a typo in a security control must
// not quietly widen it.
func parseDLPAction(value string) dlpAction {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		v = strings.TrimSpace(strings.ToLower(os.Getenv(dlpActionEnv)))
	}
	switch v {
	case "redact":
		return dlpRedact
	case "audit", "log", "detect":
		return dlpAudit
	default:
		return dlpBlock
	}
}

// redactionMarker replaces a finding. It names what happened, because a support
// ticket about a field that silently turned into asterisks costs more than the
// four extra bytes.
var redactionMarker = []byte("[REDACTED]")

// dlpRedactor removes every data-leak finding from a response body.
//
// It runs the detectors itself rather than using the engine's reported match,
// because the engine stops at the decision it is going to act on. Redacting only
// that one and forwarding the rest would leave the second card number in the
// response — a redaction that removes some of the leak is worse than a block,
// since it reports success.
//
// It is built once per engine and is safe for concurrent use: the operators are
// stateless and nothing here is retained between calls.
type dlpRedactor struct {
	ops []rules.Operator
}

// newDLPRedactor builds a redactor over the data-leak rules active at pl.
func newDLPRedactor(paranoiaLevel int) *dlpRedactor {
	set := waf.DLPResponseRules(paranoiaLevel)
	ops := make([]rules.Operator, 0, len(set))
	for i := range set {
		if set[i].Op != nil {
			ops = append(ops, set[i].Op)
		}
	}
	return &dlpRedactor{ops: ops}
}

// maxRedactionsPerBody bounds the work one response can cause. A body that
// somehow contains thousands of findings is a dump, not a page, and the honest
// response to it is to stop redacting and let the caller block instead.
const maxRedactionsPerBody = 512

// Redact returns body with every finding replaced, and how many it replaced.
//
// A zero count means the body is unchanged and the caller still holds a leak it
// has not dealt with — which is why the count is returned rather than a bool
// that a caller could read as "handled".
func (r *dlpRedactor) Redact(body []byte) (out []byte, count int) {
	spans := r.findAll(body)
	if len(spans) == 0 {
		return body, 0
	}

	out = make([]byte, 0, len(body))
	prev := 0
	for _, s := range spans {
		out = append(out, body[prev:s.start]...)
		out = append(out, redactionMarker...)
		prev = s.end
	}
	return append(out, body[prev:]...), len(spans)
}

// byteSpan is a half-open range of body bytes to remove.
type byteSpan struct{ start, end int }

// findAll returns every finding in body, sorted and with overlaps merged.
//
// Overlap is not hypothetical: a connection string carrying a password and a
// cloud key can both match across the same bytes, and splicing two overlapping
// spans independently would corrupt the output.
func (r *dlpRedactor) findAll(body []byte) []byteSpan {
	var spans []byteSpan
	for _, op := range r.ops {
		for off := 0; off < len(body) && len(spans) < maxRedactionsPerBody; {
			m, ok := op.Eval(nil, body[off:])
			if !ok || m.Span.Len == 0 {
				break
			}
			start := off + int(m.Span.Off)
			end := start + int(m.Span.Len)
			spans = append(spans, byteSpan{start: start, end: end})
			off = end
		}
	}
	return mergeSpans(spans)
}

// mergeSpans sorts spans by start and folds overlapping or touching ones
// together.
func mergeSpans(spans []byteSpan) []byteSpan {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// isDLPDecision reports whether a decision came from the data-leak corpus, so
// the configured action applies to it and not to the rest of the WAF.
func isDLPDecision(id types.RuleID) bool { return waf.IsDLPRule(id) }
