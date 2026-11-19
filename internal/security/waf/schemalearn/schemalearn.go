// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package schemalearn drafts a route's OpenAPI document from the requests the
// route forwards (ADR 0099).
//
// A route can be checked against an OpenAPI document (ADR 0095), and most
// routes have none. This watches a route's traffic and drafts one: which
// paths, which query parameters, and the narrowest type every value seen has
// fit. The draft is shown to an operator, who reads it and decides whether to
// use it. Nothing here enforces anything.
//
// The learning is gwaf's (schema/infer), and it keeps shapes only: no value,
// no hash of one, no enumeration. So unlike the request sample (ADR 0097)
// there is no traffic here to protect, only parameter names and path
// templates.
//
// Everything is in memory and bounded: at most MaxRoutes routes, each within
// infer's limits. A restart forgets it.
package schemalearn

import (
	"bytes"
	"net/url"
	"sort"
	"sync"

	"github.com/gsoultan/gwaf/schema/infer"
)

// MaxRoutes is how many routes may be learning at once. A route past it is
// not learned and Drafts says how many were turned away.
const MaxRoutes = 64

// maxQueryPairs bounds what one request contributes. infer keeps at most its
// own limit of parameters per operation; this bounds the work of offering
// them.
const maxQueryPairs = 64

// route is one route's learner. The lock is only ever tried: a request that
// finds it held is not learned from, so learning never makes a request wait.
type route struct {
	mu      sync.Mutex
	learner *infer.Learner
}

// Book holds the learners of every learning route. It is safe for concurrent
// use.
type Book struct {
	mu       sync.RWMutex
	routes   map[string]*route
	rejected int
}

// NewBook returns an empty book.
func NewBook() *Book { return &Book{routes: make(map[string]*route)} }

// Shared is the process's book: the WAF of every learning route writes to it
// and the management API reads it.
var Shared = sync.OnceValue(NewBook)

// For returns the handle a route observes through, or nil when the book is
// full. It is called when a route's WAF is built, not per request.
func (b *Book) For(routeID string) *Handle {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.routes[routeID]
	if r == nil {
		if len(b.routes) >= MaxRoutes {
			b.rejected++
			return nil
		}
		r = &route{learner: infer.New(infer.DefaultLimits())}
		b.routes[routeID] = r
	}
	return &Handle{route: r}
}

// Forget drops what was learned for a route and reports whether there was
// anything. The route's Handle keeps working and starts from nothing.
func (b *Book) Forget(routeID string) bool {
	b.mu.RLock()
	r := b.routes[routeID]
	b.mu.RUnlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	r.learner = infer.New(infer.DefaultLimits())
	r.mu.Unlock()
	return true
}

// Handle is what a route's WAF observes through.
type Handle struct{ route *route }

// Observe learns the shape of one request, given as the method, path and raw
// query the client sent. It never blocks: if another request on the route is
// being learned from at this moment, this one is skipped. A draft is built
// from thousands of requests and does not need every one.
func (h *Handle) Observe(method, path, rawQuery string) {
	if h == nil || !h.route.mu.TryLock() {
		return
	}
	defer h.route.mu.Unlock()
	h.route.learner.Observe(method, path, queryPairs(rawQuery))
}

func queryPairs(rawQuery string) []infer.Pair {
	if rawQuery == "" {
		return nil
	}
	// A query that does not parse contributes what did.
	query, _ := url.ParseQuery(rawQuery)
	pairs := make([]infer.Pair, 0, min(len(query), maxQueryPairs))
	for name, values := range query {
		for _, v := range values {
			if len(pairs) == maxQueryPairs {
				return pairs
			}
			pairs = append(pairs, infer.Pair{Name: name, Value: v})
		}
	}
	return pairs
}

// Draft is what one route has learned.
type Draft struct {
	Route string `json:"route"`
	// Observed is how many requests were learned from.
	Observed uint64 `json:"observed"`
	// Operations is how many method and path pairs the document describes.
	// 0 means nothing has been seen often enough yet, and Document is empty.
	Operations int `json:"operations"`
	// DroppedOperations and DroppedParameters count what was past a limit or
	// had a name that could not be used, so a draft that is missing something
	// says so.
	DroppedOperations uint64 `json:"droppedOperations"`
	DroppedParameters uint64 `json:"droppedParameters"`
	// MinSamples is how many times an operation or parameter must be seen
	// before it is drafted.
	MinSamples int `json:"minSamples"`
	// Document is the OpenAPI document, as JSON.
	Document string `json:"document"`
}

// Drafts returns what every learning route has learned, by route name, and
// how many routes were turned away because the book was full.
func (b *Book) Drafts() (drafts []Draft, rejected int) {
	b.mu.RLock()
	ids := make([]string, 0, len(b.routes))
	for id := range b.routes {
		ids = append(ids, id)
	}
	routes := make(map[string]*route, len(b.routes))
	for id, r := range b.routes {
		routes[id] = r
	}
	rejected = b.rejected
	b.mu.RUnlock()

	sort.Strings(ids)
	drafts = make([]Draft, 0, len(ids))
	for _, id := range ids {
		drafts = append(drafts, routes[id].draft(id))
	}
	return drafts, rejected
}

func (r *route) draft(id string) Draft {
	// A reader waits for the lock; a request never does (Observe).
	r.mu.Lock()
	ops := r.learner.Draft()
	st := r.learner.Stats()
	r.mu.Unlock()

	d := Draft{
		Route: id, Observed: st.Observed, Operations: len(ops),
		DroppedOperations: st.DroppedOperations, DroppedParameters: st.DroppedFields,
		MinSamples: infer.DefaultLimits().MinSamples,
	}
	if len(ops) == 0 {
		return d
	}
	var doc bytes.Buffer
	if err := infer.WriteOpenAPI(&doc, "Draft learned from traffic on "+id, ops); err == nil {
		d.Document = doc.String()
	}
	return d
}
