// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
)

type contextKey string

const idKey contextKey = "request_id"

// GetID returns the request ID from the request context or "unknown".
func GetID(r *http.Request) string {
	if id, ok := r.Context().Value(idKey).(string); ok {
		return id
	}
	return "unknown"
}

// WithID adds a request ID to the context.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idKey, id)
}

// HeaderRequestID is the request id header in its canonical spelling. The
// header functions canonicalize whatever spelling they are given, so "X-Request-ID"
// reaches the wire as this, and giving them this spelling to begin with spares
// an allocation on every request.
const HeaderRequestID = "X-Request-Id"

// GenerateID creates a new unique request ID: "req-" and sixteen hex digits
// from crypto/rand.
//
// It is cut from a batch (idBatch), so a request does not allocate for it.
func GenerateID() string {
	b := idBatches.Get().(*idBatch)
	id := b.id()
	idBatches.Put(b)
	return id
}

// NewIDHeader is GenerateID with the response header value that carries the
// ID: what the entrypoint needs, without the allocation http.Header.Set makes
// for the one-element slice.
func NewIDHeader() (string, []string) {
	b := idBatches.Get().(*idBatch)
	id := b.id()
	v := b.value(id)
	idBatches.Put(b)
	return id, v
}

// IDHeaderValue is the response header value for an ID the request supplied.
func IDHeaderValue(id string) []string {
	b := idBatches.Get().(*idBatch)
	v := b.value(id)
	idBatches.Put(b)
	return v
}

const (
	// idLen is len("req-") plus sixteen hex digits.
	idLen = 20
	// idBatchSize is how many IDs, and how many header values, one
	// allocation provides. It is also the bound on what a retained ID pins: an
	// ID shares its string with the rest of its batch, so one kept in a trace or
	// a log keeps idBatchSize*idLen bytes alive rather than idLen, and a header
	// value keeps idBatchSize slice elements -- 160 and 128 bytes. Eight brings
	// the per-request cost to an eighth of an allocation each without letting
	// that factor grow.
	idBatchSize = 8
)

// idBatch is IDs and header values handed out one at a time, refilled when
// spent. A batch is owned by whoever took it from idBatches until they put it
// back, so nothing in it needs a lock; what it hands out is never written
// again by the batch: an ID is a substring of an immutable string, and a value
// is a slot no later caller is given.
type idBatch struct {
	ids     string
	nextID  int
	vals    []string
	nextVal int
}

var idBatches = sync.Pool{New: func() any { return &idBatch{nextID: idBatchSize, nextVal: idBatchSize} }}

func (b *idBatch) id() string {
	if b.nextID == idBatchSize {
		b.ids = newIDs()
		b.nextID = 0
	}
	i := b.nextID * idLen
	b.nextID++
	return b.ids[i : i+idLen]
}

// value returns a one-element slice holding id. Its capacity is one, so an
// append to it -- a header added under the same name -- reallocates rather than
// writing into the next caller's slot.
func (b *idBatch) value(id string) []string {
	if b.nextVal == idBatchSize {
		b.vals = make([]string, idBatchSize)
		b.nextVal = 0
	}
	i := b.nextVal
	b.nextVal++
	v := b.vals[i : i+1 : i+1]
	v[0] = id
	return v
}

// newIDs is idBatchSize IDs back to back in one string, from one read of
// crypto/rand.
func newIDs() string {
	var raw [idBatchSize * 8]byte
	_, _ = rand.Read(raw[:])
	var buf [idBatchSize * idLen]byte
	for i := range idBatchSize {
		out := buf[i*idLen : (i+1)*idLen]
		copy(out, "req-")
		hex.Encode(out[4:], raw[i*8:(i+1)*8])
	}
	return string(buf[:])
}
