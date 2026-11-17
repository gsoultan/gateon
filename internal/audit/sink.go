// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"slices"
	"sync"
	"sync/atomic"
)

// Sink receives every entry the audit log stores, once it is stored, on the
// goroutine that stored it. It must not block: a sign-in, a configuration save
// and the system-entry writer all wait for it. A sink that has work to do
// queues the entry, bounded, and does it on a goroutine of its own.
//
// The Broadcaster already handed entries on, to the Command Center's live
// view, and drops one for a subscriber whose channel is full. That is the
// right trade for a screen. It is the wrong one for the two readers ADR 0099
// adds -- the alert on administrator activity and the copy sent off the host
// -- because an attacker who floods the log with system entries chooses which
// of the administrator's entries is dropped. A sink sees every entry and
// decides for itself what it can afford to keep.
type Sink func(AuditEntry)

type sinkEntry struct {
	id int
	fn Sink
}

var (
	sinksMu   sync.Mutex
	sinkSeq   int
	sinkSlice atomic.Pointer[[]sinkEntry]
)

// AddSink registers s for every entry stored from now on, and returns the
// function that removes it. Delivery reads the registered list without a
// lock; adding and removing copy it.
func AddSink(s Sink) (remove func()) {
	if s == nil {
		return func() {}
	}
	sinksMu.Lock()
	defer sinksMu.Unlock()
	sinkSeq++
	id := sinkSeq
	next := append(currentSinks(), sinkEntry{id: id, fn: s})
	sinkSlice.Store(&next)
	return func() { removeSink(id) }
}

func removeSink(id int) {
	sinksMu.Lock()
	defer sinksMu.Unlock()
	next := slices.DeleteFunc(currentSinks(), func(e sinkEntry) bool { return e.id == id })
	sinkSlice.Store(&next)
}

// currentSinks is a copy of the registered list, safe to append to.
func currentSinks() []sinkEntry {
	p := sinkSlice.Load()
	if p == nil {
		return nil
	}
	return slices.Clone(*p)
}

// deliver hands e to every sink, and then to the Broadcaster.
func (m *AuditManager) deliver(e AuditEntry) {
	if p := sinkSlice.Load(); p != nil {
		for _, s := range *p {
			s.fn(e)
		}
	}
	if m.Broadcaster != nil {
		m.Broadcaster.Broadcast(e)
	}
}
