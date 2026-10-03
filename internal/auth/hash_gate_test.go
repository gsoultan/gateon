// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/auth/admission"
)

// hashWatch counts the bcrypt comparisons running at once, and the most that
// ever did, by wrapping compareHash for one test. Not parallel-safe: no test
// that uses it may call t.Parallel.
type hashWatch struct {
	inFlight, peak, calls atomic.Int64
}

func watchHashes(t *testing.T) *hashWatch {
	t.Helper()
	w := &hashWatch{}
	real := compareHash
	compareHash = func(hash, password []byte) error {
		w.calls.Add(1)
		n := w.inFlight.Add(1)
		defer w.inFlight.Add(-1)
		for {
			p := w.peak.Load()
			if n <= p || w.peak.CompareAndSwap(p, n) {
				break
			}
		}
		return real(hash, password)
	}
	t.Cleanup(func() { compareHash = real })
	return w
}

// signInStorm makes callers sign-in attempts at once, each for a username
// that does not exist and from an address of its own -- so neither the
// per-pair nor the per-account lockout refuses any -- and reports how many
// were refused as busy and how many as wrong passwords.
func signInStorm(m *Manager, callers int) (busy, refused int64) {
	var b, r atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			<-start
			_, _, err := m.Authenticate("nobody-"+strconv.Itoa(i), "a-guess-at-it",
				"203.0."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250))
			switch {
			case errors.Is(err, ErrBusy):
				b.Add(1)
			case errors.Is(err, ErrInvalidCredentials):
				r.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	return b.Load(), r.Load()
}

// TestConcurrentSignInsNeverHashPastTheGate is MGMT-N3's CPU half. Every
// sign-in for a name that does not exist pays for a bcrypt comparison at the
// production cost (ADR 0050), and nothing bounded how many ran at once: one
// address on /v1/auth/2fa/enroll kept ten to eleven cores busy and took the
// data plane's median from 0.7 to 86 ms. At most the gate's size may hash at
// once; the rest are refused as busy, before any hash, rather than queued.
func TestConcurrentSignInsNeverHashPastTheGate(t *testing.T) {
	t.Setenv(admission.HashConcurrencyEnv, "2")
	m := newTestManager(t)
	w := watchHashes(t)

	busy, refused := signInStorm(m, 32)

	t.Logf("32 concurrent sign-ins: %d hashed, %d refused as busy, peak %d hashes at once",
		w.calls.Load(), busy, w.peak.Load())
	if p := w.peak.Load(); p > 2 {
		t.Fatalf("%d bcrypt comparisons ran at once; the gate allows 2", p)
	}
	if busy == 0 || refused == 0 {
		t.Fatalf("busy %d, wrong-password %d: want both, or the gate refused everything or nothing", busy, refused)
	}
	if busy+refused != 32 {
		t.Errorf("busy %d + wrong-password %d != 32 attempts", busy, refused)
	}
	if w.calls.Load() != refused {
		t.Errorf("%d comparisons for %d attempts that were checked: a refused attempt must not hash", w.calls.Load(), refused)
	}
}

// fillGate takes every general slot of m's gate until the test ends, as a
// flood from many addresses would.
func fillGate(t *testing.T, m *Manager) {
	t.Helper()
	for {
		s, ok := m.hashes.TryEnter()
		if !ok {
			return
		}
		t.Cleanup(s.Release)
	}
}

// TestTheOwnerSignsInFromAKnownSourceWhileTheGateIsFull keeps ADR 0050's
// promise under ADR 0053's gate: a flood from addresses the account has never
// used fills every general slot, and the owner, from a source they have signed
// in from before, still gets the reserve. A stranger naming the same account
// from elsewhere, and a name that does not exist, are both refused as busy --
// before any hash, so the refusal says nothing about which accounts exist.
func TestTheOwnerSignsInFromAKnownSourceWhileTheGateIsFull(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "admin", ownerPass)
	if _, _, err := m.Authenticate("admin", ownerPass, ownerAddr); err != nil {
		t.Fatalf("the owner's first sign-in: %v", err)
	}
	w := watchHashes(t)
	fillGate(t, m)

	if _, _, err := m.Authenticate("admin", ownerPass, attackerAddr); !errors.Is(err, ErrBusy) {
		t.Errorf("the right password from a source the account never used, gate full: err = %v, want ErrBusy", err)
	}
	if _, _, err := m.Authenticate("nobody", "a-guess-at-it", ownerAddr); !errors.Is(err, ErrBusy) {
		t.Errorf("an unknown name, gate full: err = %v, want ErrBusy", err)
	}
	if n := w.calls.Load(); n != 0 {
		t.Fatalf("%d hashes ran for attempts refused as busy", n)
	}
	token, _, err := m.Authenticate("admin", ownerPass, ownerAddr)
	if err != nil || token == "" {
		t.Fatalf("the owner from their known source, gate full: err = %v, want a session", err)
	}
}
