// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package connguard

import (
	"net/netip"
	"sync"
	"time"
)

// CoolOff refuses new connections, for a short while, from an address whose
// HTTP/2 connection was closed for rapid reset.
//
// Closing the connection alone bounded memory but not CPU. In the 2026-11-17
// re-run of the review's lab, 128 rapid-reset connections closed at the reset
// limit simply reconnected: the gateway still parsed some two million frames
// a second, and a legitimate client waited 2.7 s at the median. Nothing about
// a reconnect from the same address is more trustworthy than the connection
// just closed, so for the cool-off it is refused at accept, before any TLS
// work, which costs the gateway a close.
//
// It is the only cross-connection state the entrypoint keeps about a client,
// and it is bounded: at most maxEntries addresses, each forgotten once its
// cool-off passes. An address set beyond that is not cooled off -- its
// connections are still closed at the reset limit, as without CoolOff.
// Addresses behind one NAT share a cool-off; the window is kept short for
// that reason.
//
// CoolOff is safe for concurrent use. It is consulted on accept, never on the
// request path. A nil *CoolOff refuses nothing.
type CoolOff struct {
	mu         sync.Mutex
	until      map[netip.Addr]time.Time
	d          time.Duration
	maxEntries int
}

// NewCoolOff returns a CoolOff of d per address, tracking at most maxEntries
// addresses at once. It returns nil, the guard off, when d or maxEntries is
// not positive.
func NewCoolOff(d time.Duration, maxEntries int) *CoolOff {
	if d <= 0 || maxEntries <= 0 {
		return nil
	}
	return &CoolOff{until: make(map[netip.Addr]time.Time), d: d, maxEntries: maxEntries}
}

// Start begins key's cool-off at now.
func (c *CoolOff) Start(key netip.Addr, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.until[key]; !ok && len(c.until) >= c.maxEntries {
		c.sweepLocked(now)
		if len(c.until) >= c.maxEntries {
			return
		}
	}
	c.until[key] = now.Add(c.d)
}

// Refuses reports whether key is cooling off at now.
func (c *CoolOff) Refuses(key netip.Addr, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.until) == 0 {
		return false
	}
	t, ok := c.until[key]
	if !ok {
		return false
	}
	if now.Before(t) {
		return true
	}
	delete(c.until, key)
	return false
}

// Len is how many addresses are tracked, for tests and metrics.
func (c *CoolOff) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.until)
}

func (c *CoolOff) sweepLocked(now time.Time) {
	for k, t := range c.until {
		if !now.Before(t) {
			delete(c.until, k)
		}
	}
}
