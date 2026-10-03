// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package lockout throttles password guessing without letting the guesser lock
// the owner out. See ADR 0050.
//
// The lockout it replaces counted failures per username: five wrong passwords
// from anyone locked the account for fifteen minutes, for everyone, the right
// password from the owner's own address included -- and five requests every
// fifteen minutes kept an administrator out for as long as an attacker cared
// to send them.
//
// Failures are now counted twice, and neither count stops the owner:
//
//   - Per account and source. Five failures for one account from one source --
//     an IPv4 /24 or an IPv6 /64, the unit an attacker holds -- lock that pair
//     for fifteen minutes. Nobody else is affected.
//   - Per account, across sources: the backstop for an attacker who spreads
//     guesses over many sources. Twenty failures within fifteen minutes put the
//     account under attack for fifteen minutes, and every attempt refused under
//     it renews that. While it holds, only a source the account has signed in
//     from before may try at all; the caller decides which those are.
//
// A single source therefore gets five guesses per fifteen minutes, and any
// number of sources together get twenty before only the owner's own may try.
package lockout

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/simplelru"
)

const (
	// PairLimit is how many failures one source may make against one account
	// before that pair is locked.
	PairLimit = 5
	// PairLock is how long a locked pair stays locked.
	PairLock = 15 * time.Minute
	// AccountLimit is how many failures against one account, from any number
	// of sources, within AccountWindow put it under attack.
	AccountLimit = 20
	// AccountWindow is the span AccountLimit counts over, and how long an
	// account stays under attack after the last attempt that renewed it.
	AccountWindow = 15 * time.Minute
)

// Decision is what Check answers for an attempt.
type Decision int

const (
	// Allow lets the attempt be checked.
	Allow Decision = iota
	// PairLocked refuses it: this source has failed too often for this account.
	PairLocked
	// UnderAttack refuses it unless the source is one the account knows; the
	// caller decides, and calls Renew when it refuses.
	UnderAttack
)

// Bounds name the size of a Tracker's two tables. Both are LRUs: the least
// recently touched entry is evicted first.
type Bounds struct {
	Pairs    int
	Accounts int
}

// DefaultBounds hold about 16k (account, source) pairs and 4k accounts, under
// 3 MiB together.
var DefaultBounds = Bounds{Pairs: 16384, Accounts: 4096}

type window struct {
	failures    int
	start       time.Time
	lockedUntil time.Time
}

// Tracker counts failed attempts. Safe for concurrent use; sign-in is not a
// hot path, and one mutex orders the two tables.
type Tracker struct {
	mu       sync.Mutex
	pairs    *simplelru.LRU
	accounts *simplelru.LRU
	now      func() time.Time
}

// New makes a Tracker with the given bounds; a bound below 1 is 1.
func New(b Bounds) *Tracker {
	pairs, _ := simplelru.NewLRU(max(b.Pairs, 1), nil)
	accounts, _ := simplelru.NewLRU(max(b.Accounts, 1), nil)
	return &Tracker{pairs: pairs, accounts: accounts, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (t *Tracker) SetClock(now func() time.Time) {
	t.mu.Lock()
	t.now = now
	t.mu.Unlock()
}

type pairKey struct{ account, source string }

// Check answers whether an attempt for account from source may proceed.
// source is a Prefix.
func (t *Tracker) Check(account, source string) Decision {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if w := t.get(t.pairs, pairKey{account, source}); w != nil && now.Before(w.lockedUntil) {
		return PairLocked
	}
	if w := t.get(t.accounts, account); w != nil && now.Before(w.lockedUntil) {
		return UnderAttack
	}
	return Allow
}

// Fail records a wrong password for account from source.
func (t *Tracker) Fail(account, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.count(t.pairs, pairKey{account, source}, now, PairLimit, PairLock)
	t.count(t.accounts, account, now, AccountLimit, AccountWindow)
}

// Renew keeps account under attack for another AccountWindow. It is called
// for an attempt refused because the account was, so an attack that goes on
// keeps strangers out for as long as it goes on.
func (t *Tracker) Renew(account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if w := t.get(t.accounts, account); w != nil {
		w.lockedUntil = t.now().Add(AccountWindow)
	}
}

// Succeed records a right password for account from source: that pair's
// count is cleared. The account's count is not -- the owner signing in from
// home does not hand the attacker a fresh twenty guesses.
func (t *Tracker) Succeed(account, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pairs.Remove(pairKey{account, source})
}

func (t *Tracker) get(table *simplelru.LRU, key any) *window {
	v, ok := table.Get(key)
	if !ok {
		return nil
	}
	w, ok := v.(*window)
	if !ok {
		return nil
	}
	return w
}

// count adds a failure to key's window, starting a new window when the last
// one is over, and locks it for lock once limit is reached.
func (t *Tracker) count(table *simplelru.LRU, key any, now time.Time, limit int, lock time.Duration) {
	w := t.get(table, key)
	if w == nil || (now.Sub(w.start) >= lock && !now.Before(w.lockedUntil)) {
		w = &window{start: now}
		table.Add(key, w)
	}
	w.failures++
	if w.failures >= limit {
		w.lockedUntil = now.Add(lock)
		w.failures = 0
		w.start = now
	}
}

// Prefix is the source an attempt is counted against: the /24 of an IPv4
// address and the /64 of an IPv6 one, as text. addr may carry a port. An
// address that does not parse is "", one shared source: a caller that cannot
// say where it is gets no allowance of its own.
func Prefix(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	p, err := ip.WithZone("").Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}
