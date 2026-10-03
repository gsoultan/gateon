// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package admission

import (
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/simplelru"
)

// MaxSources is how many clients Sources keeps a bucket for. Its keys are
// netip.Prefix values, a fixed size, so the table is bounded in bytes as well
// as entries: about 3 MiB full. The least recently seen client is evicted
// first; an evicted client starts again with a full bucket, which is why the
// Gate, and not this table, is what bounds a client with many addresses.
const MaxSources = 16384

// bucket is one client's allowance: tokens left as of last.
type bucket struct {
	tokens float64
	last   time.Time
}

// Sources is a token bucket per client for the public sign-in endpoints. Each
// request spends one token; a client starts with burst tokens and earns them
// back at perSecond. Safe for concurrent use; these endpoints are not a hot
// path, and one mutex orders the table.
type Sources struct {
	mu        sync.Mutex
	buckets   *simplelru.LRU
	perSecond float64
	burst     float64
	now       func() time.Time
}

// NewSources makes a Sources that allows perMinute requests a minute per
// client, perMinute of them at once; perMinute below 1 is 1.
func NewSources(perMinute int) *Sources {
	perMinute = max(perMinute, 1)
	table, _ := simplelru.NewLRU(MaxSources, nil)
	return &Sources{
		buckets:   table,
		perSecond: float64(perMinute) / 60,
		burst:     float64(perMinute),
		now:       time.Now,
	}
}

// SetClock replaces the clock, for tests.
func (s *Sources) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// Take spends one request for the client at addr. It reports whether the
// client had one to spend, and when it does not, how long until it will.
func (s *Sources) Take(addr string) (bool, time.Duration) {
	key := SourceOf(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	b := s.bucketFor(key, now)
	b.tokens = min(s.burst, b.tokens+now.Sub(b.last).Seconds()*s.perSecond)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := (1 - b.tokens) / s.perSecond
	return false, time.Duration(math.Ceil(wait)) * time.Second
}

// bucketFor is key's bucket, a full one for a client not seen before (or
// evicted since).
func (s *Sources) bucketFor(key netip.Prefix, now time.Time) *bucket {
	if v, ok := s.buckets.Get(key); ok {
		if b, ok := v.(*bucket); ok {
			return b
		}
	}
	b := &bucket{tokens: s.burst, last: now}
	s.buckets.Add(key, b)
	return b
}

// Len is how many clients have a bucket.
func (s *Sources) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buckets.Len()
}

// SourceOf is the client a request is counted against: an IPv4 address
// (a /32), or the /64 of an IPv6 one -- the unit an IPv6 client is handed, so
// that one client cannot step through 2^64 addresses with a fresh bucket for
// each. addr may carry a port. An address that does not parse is the zero
// Prefix, one shared client: a caller that cannot say where it is gets no
// allowance of its own.
func SourceOf(addr string) netip.Prefix {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}
	}
	ip = ip.Unmap().WithZone("")
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}
