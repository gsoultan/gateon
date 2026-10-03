// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package admission bounds what an anonymous client can make the gateway
// spend on its public sign-in endpoints, per client and in total (ADR 0053).
//
// A sign-in costs a bcrypt comparison at the production cost -- tens of
// milliseconds of one core -- and since ADR 0050 an unknown username costs the
// same as a real one, so that the answer does not say which exist. Nothing
// bounded how many ran: from one address, POST /v1/auth/2fa/enroll kept ten to
// eleven cores busy and moved the data plane's median latency from 0.7 to
// 86 ms. Two bounds, applied in this order:
//
//   - Sources: a token bucket per client -- an IPv4 address, an IPv6 /64 --
//     spent by every request to an endpoint that can reach a password check,
//     before the request is read. It bounds what one client costs.
//   - Gate: how many hashes run at once, in the whole process. It bounds what
//     every client together costs, however many addresses they have. A request
//     that finds it full is refused at once, before any hash, and never queued.
package admission

import (
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrBusy refuses a password check because the gate is full. It is decided
// before any hash, so its answer and its timing are the same for every
// username. It carries the gRPC status ResourceExhausted, so every transport
// answers it as one -- 429 over REST and Connect -- however many layers return
// it unchanged.
var ErrBusy error = busyError{}

const busyMessage = "the gateway is checking too many sign-ins at once; try again in a moment"

type busyError struct{}

func (busyError) Error() string { return busyMessage }

// GRPCStatus is ResourceExhausted.
func (busyError) GRPCStatus() *status.Status {
	return status.New(codes.ResourceExhausted, busyMessage)
}

// BusyRetryAfter is what a refusal for a full gate tells the client to wait:
// a hash takes tens of milliseconds, so a slot is free again well within it.
const BusyRetryAfter = time.Second

// maxWaiters bounds the callers Enter lets wait at once. They are signed-in
// callers (a password change, a 2FA enrolment), each of which already passed a
// lockout, so this is a backstop, not a budget.
const maxWaiters = 64

// Gate bounds the password hashes running at once. Its slots are of two kinds:
// the general ones, which anything may take, and one reserve, which only an
// attempt from a source the account has signed in from before may take, so a
// flood that fills the general slots from addresses the account has never used
// cannot keep its owner out (ADR 0050's guarantee, kept under ADR 0053).
type Gate struct {
	slots   chan struct{}
	reserve chan struct{}
	waiters atomic.Int32
}

// NewGate makes a Gate with n general slots and one reserve; n below 1 is 1.
func NewGate(n int) *Gate {
	return &Gate{slots: make(chan struct{}, max(n, 1)), reserve: make(chan struct{}, 1)}
}

// Size is the most hashes that can run at once: the general slots and the
// reserve.
func (g *Gate) Size() int { return cap(g.slots) + cap(g.reserve) }

// Slot is a held place in a Gate. Release it exactly once.
type Slot struct{ ch chan struct{} }

// Release gives the slot back.
func (s Slot) Release() { <-s.ch }

// TryEnter takes a general slot if one is free now.
func (g *Gate) TryEnter() (Slot, bool) {
	return tryTake(g.slots)
}

// TryEnterReserved takes the reserve if it is free now. Only an attempt from a
// source the named account already knows may ask.
func (g *Gate) TryEnterReserved() (Slot, bool) {
	return tryTake(g.reserve)
}

// Enter waits up to wait for a general slot, for work a signed-in caller asked
// for. It refuses at once when maxWaiters callers are already waiting.
func (g *Gate) Enter(wait time.Duration) (Slot, bool) {
	if s, ok := g.TryEnter(); ok {
		return s, true
	}
	if g.waiters.Add(1) > maxWaiters {
		g.waiters.Add(-1)
		return Slot{}, false
	}
	defer g.waiters.Add(-1)
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
		return Slot{ch: g.slots}, true
	case <-t.C:
		return Slot{}, false
	}
}

func tryTake(ch chan struct{}) (Slot, bool) {
	select {
	case ch <- struct{}{}:
		return Slot{ch: ch}, true
	default:
		return Slot{}, false
	}
}
