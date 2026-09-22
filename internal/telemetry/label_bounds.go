// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// A Prometheus label value taken from a request is a map key an attacker
// chooses. MetricVec keeps every series it has ever seen for the life of the
// process -- nothing in this tree calls Reset or DeleteLabelValues on the
// request-path vectors -- so an unbounded label is a remote OOM with no
// authentication required.
//
// Measured on the real server before these bounds existed: 200,000 distinct
// Host values cost 275.8 MiB (1,446 B per value, three series each), and a
// 60 KB Host is legal under the 1 MiB header cap, at 133 KB of permanent heap
// per request. Roughly fifteen thousand ordinary GETs exhausted the 2 GB
// target host. Novel method tokens were cheaper still by bandwidth: 2,319 B
// per token, about 45 MB of traffic to the same end.
//
// The per-IP series next to these were already recognised as this bug and put
// behind GATEON_PER_IP_METRICS. The domain and method labels never got the
// same treatment; they do now, by capping distinct values rather than by
// switching the metric off, so an ordinary deployment keeps its per-domain
// breakdown and only a deployment under cardinality attack loses detail.

// LabelOverflow is the value recorded once a bounded label has seen its
// maximum number of distinct values. A single series absorbs the rest, so the
// metric stays readable and the memory stops growing.
const LabelOverflow = "other"

// maxDistinctDomains bounds the per-domain series. A gateway fronting more
// than this many real virtual hosts is well outside the deployment this
// product targets, and the overflow bucket keeps the total correct even then.
const maxDistinctDomains = 2000

// boundedLabels admits a fixed number of distinct values and folds the rest
// into LabelOverflow.
//
// Deliberately never evicts. Eviction would let an attacker displace the real
// domains an operator watches, turning a memory bug into an observability one;
// admitting the first N and bucketing the rest keeps whatever the gateway saw
// first, which in practice is the configured traffic.
type boundedLabels struct {
	max  int
	seen sync.Map
	n    atomic.Int64
}

func (b *boundedLabels) value(v string) string {
	if v == "" {
		return "unknown"
	}
	if _, ok := b.seen.Load(v); ok {
		return v
	}
	if b.n.Load() >= int64(b.max) {
		return LabelOverflow
	}
	// A race here can admit a few values past max, which is harmless: the
	// bound is a ceiling on growth, not an exact quota.
	if _, loaded := b.seen.LoadOrStore(v, struct{}{}); !loaded {
		b.n.Add(1)
	}
	return v
}

var domainLabels = &boundedLabels{max: maxDistinctDomains}

// DomainLabel bounds a Host-derived metric label.
func DomainLabel(domain string) string { return domainLabels.value(domain) }

// knownMethods is the closed set of HTTP methods worth their own series. Go's
// server accepts any RFC 7230 token as a method, so without this a client can
// mint a series per request with a five-byte request line.
var knownMethods = map[string]struct{}{
	http.MethodGet: {}, http.MethodHead: {}, http.MethodPost: {},
	http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
	http.MethodConnect: {}, http.MethodOptions: {}, http.MethodTrace: {},
	// Not in net/http's constants but routinely proxied.
	"PROPFIND": {}, "PROPPATCH": {}, "MKCOL": {}, "COPY": {}, "MOVE": {},
	"LOCK": {}, "UNLOCK": {}, "REPORT": {}, "SEARCH": {},
}

// MethodLabel folds any method outside the known set into LabelOverflow.
func MethodLabel(method string) string {
	if _, ok := knownMethods[method]; ok {
		return method
	}
	return LabelOverflow
}
