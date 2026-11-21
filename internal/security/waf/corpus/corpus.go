// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package corpus keeps a small sample of the requests a WAF let through, so
// the WAF can be tuned against the traffic it actually protects.
//
// gwaf's toolchain tunes from a corpus of benign requests: `gwaf tune`
// suggests the narrowest exceptions for the false positives it measures, and
// `gwaf tune -schema` drafts an OpenAPI document. Both read one JSON Lines
// shape (gwaf's calibrate.Request), and until now nothing in the gateway
// could produce it, so the corpus was written by hand and measured the
// imagination of whoever wrote it (ADR 0097).
//
// What is kept is the least that tuning needs, and less than an access log
// holds: method, path, query parameters and request headers. No body, no
// client address, no time, and no credential -- see Capture.
//
// The sample lives in memory, in a ring of fixed size. Nothing is written to
// disk on the request path, nothing survives a restart, and a new entry
// displaces the oldest.
package corpus

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/security/redact"
)

// The bounds on one entry. A request past any of them is not sampled at all:
// a truncated value is a value the client never sent, and tuning against it
// would measure the truncation.
const (
	// MaxEntryBytes is the most one entry holds across its path, names and
	// values. With the ring's capacity it is the sample's whole memory bound.
	MaxEntryBytes = 4 << 10

	maxPairs = 48 // query parameters and headers together
)

// Entry is one sampled request, in the shape gwaf's calibrate.Request reads.
type Entry struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
}

// Ring is a fixed-size sample. It is safe for concurrent use and takes no
// lock: the request path does one atomic add and one atomic store.
type Ring struct {
	slots []atomic.Pointer[Entry]
	next  atomic.Uint64
	tick  atomic.Uint64
}

// NewRing returns a ring that holds the last capacity entries.
func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{slots: make([]atomic.Pointer[Entry], capacity)}
}

// Due reports whether this request is the one in every rate to sample. A rate
// below 1 samples nothing.
//
// A counter rather than a random draw: it costs one atomic add, and which
// requests are sampled does not have to be unpredictable -- a client that
// could choose to be sampled gains nothing, because Add is only reached for a
// request the WAF found nothing against and the origin accepted.
func (g *Ring) Due(rate int) bool {
	if rate < 1 {
		return false
	}
	return g.tick.Add(1)%uint64(rate) == 0
}

// Add keeps e, displacing the oldest entry once the ring is full.
func (g *Ring) Add(e *Entry) {
	if e == nil {
		return
	}
	i := g.next.Add(1) - 1
	g.slots[i%uint64(len(g.slots))].Store(e)
}

// Total is how many entries the ring was ever given, displaced ones included.
func (g *Ring) Total() uint64 { return g.next.Load() }

// Len is how many entries the ring holds.
func (g *Ring) Len() int {
	n := g.next.Load()
	if n > uint64(len(g.slots)) {
		return len(g.slots)
	}
	return int(n)
}

// WriteJSONL writes the sample as JSON Lines, one entry per line, and reports
// how many it wrote.
func (g *Ring) WriteJSONL(w io.Writer) (int, error) {
	enc := json.NewEncoder(w)
	n := 0
	for i := range g.slots {
		e := g.slots[i].Load()
		if e == nil {
			continue
		}
		if err := enc.Encode(e); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Capture builds the entry for r, and reports false when r is not one to
// keep.
//
// Credentials are removed twice over. A header whose name says it carries one
// (Authorization, Cookie, an API key) is left out entirely, and so is a
// header whose value has the shape of one. A query parameter is kept under
// its name, because the name is what an exception is scoped to, with its
// value replaced by redact.Mask when the name or the value says credential.
// The masked value is not what the client sent, so a rule that fired on a
// credential cannot be tuned from this sample -- which is the right way
// round.
//
// route names the entry, so a report says where a request came from.
func Capture(r *http.Request, route string) (*Entry, bool) {
	path := r.URL.EscapedPath()
	if path == "" || path[0] != '/' {
		return nil, false
	}
	e := &Entry{
		Name:   route + " " + r.Method + " " + path,
		Method: r.Method,
		Target: path,
	}
	b := budget{bytes: MaxEntryBytes - len(path), pairs: maxPairs}
	if b.bytes < 0 {
		return nil, false
	}

	if !e.keepArgs(r, &b) || !e.keepHeaders(r, &b) {
		return nil, false
	}
	return e, true
}

// keepArgs keeps the first value of each query parameter, masking the ones
// that carry a credential, and reports false when they do not fit.
func (e *Entry) keepArgs(r *http.Request, b *budget) bool {
	query := r.URL.Query()
	if len(query) == 0 {
		return true
	}
	e.Args = make(map[string]string, len(query))
	for name, values := range query {
		if len(values) == 0 || !b.take(name, values[0]) {
			return false
		}
		v := values[0]
		if redact.IsCredentialParam(name) || redact.IsCredentialValue(v) {
			v = redact.Mask
		}
		e.Args[name] = v
	}
	return true
}

// keepHeaders keeps the first value of each header that carries no
// credential, and reports false when they do not fit.
func (e *Entry) keepHeaders(r *http.Request, b *budget) bool {
	e.Headers = make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		if len(values) == 0 || redact.IsCredentialHeader(name) {
			continue
		}
		v := values[0]
		if redact.HeaderValue(name, v) != v {
			continue
		}
		if !b.take(name, v) {
			return false
		}
		e.Headers[name] = v
	}
	return true
}

type budget struct{ bytes, pairs int }

func (b *budget) take(name, value string) bool {
	b.bytes -= len(name) + len(value)
	b.pairs--
	return b.bytes >= 0 && b.pairs >= 0
}

// Accepted reports whether a response status means the origin took the
// request as an ordinary one. A 4xx or 5xx is traffic the application itself
// rejected, and a corpus is a claim that every entry is benign.
func Accepted(status int) bool {
	return status >= http.StatusOK && status < http.StatusBadRequest
}

// ParseRate reads a sample rate: "100" keeps one request in a hundred.
// Anything that is not a positive whole number is 0, which samples nothing.
func ParseRate(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// Shared is the process's one sample. Every route that samples writes to it,
// and the management API reads it; an entry's Name says which route it came
// from. Its size is the tier's WAFCorpusEntries.
var Shared = sync.OnceValue(func() *Ring {
	if n := ParseRate(os.Getenv(EntriesEnv)); n > 0 {
		return NewRing(min(n, maxEntries))
	}
	return NewRing(config.CurrentTierDefaults().WAFCorpusEntries)
})

// EntriesEnv overrides the tier's sample size.
const EntriesEnv = "GATEON_WAF_CORPUS_ENTRIES"

// maxEntries caps what EntriesEnv may ask for: 65536 entries of 4 KiB is
// 256 MiB, and a sample larger than that is an access log.
const maxEntries = 1 << 16
