// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SessionBindingClaim is the token claim carrying the session binding. Short
// because it is encrypted into every token.
const SessionBindingClaim = "sb"

var (
	// ErrSessionRevoked means the token is cryptographically valid but the
	// account it was issued for has since changed in a way that must end every
	// live session.
	ErrSessionRevoked = errors.New("session revoked: the account was disabled, deleted, or its role or password changed")
)

// sessionBinding derives a short, stable fingerprint of the security-relevant
// state of a user row.
//
// A PASETO here is a bearer token with a fixed lifetime and, before this
// existed, nothing consulted the database on the way in: VerifyToken checked
// only the signature and the exp/nbf claims. Disabling an account, deleting it,
// demoting an administrator to viewer or rotating a leaked password therefore
// changed a row that no request path ever read, and the old token kept its
// original privileges until it expired on its own. Firing an administrator left
// them with working admin credentials for the rest of the day.
//
// Binding the token to a digest of (password hash, role, disabled) makes all
// four of those events revoke implicitly: each one changes an input, the digest
// stops matching, and every token minted before the change is refused. It needs
// no schema change and no revocation list to keep, which matters because a
// denylist is another unbounded structure to size and expire.
//
// The password hash is an input, not an output: it never leaves this function,
// and only its digest reaches the token.
func sessionBinding(passwordHash, role string, disabled bool) string {
	h := sha256.New()
	// Length-prefixed so ("ab","c") and ("a","bc") cannot collide.
	writeField(h, passwordHash)
	writeField(h, role)
	if disabled {
		writeField(h, "1")
	} else {
		writeField(h, "0")
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	var lenBuf [8]byte
	n := uint64(len(s))
	for i := range 8 {
		lenBuf[i] = byte(n >> (8 * i))
	}
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// DefaultBindingTTL bounds how long a cached session binding may be trusted.
//
// The cache is per process, and invalidation is a local map delete. In a
// single-instance deployment that is exact. Across several instances sharing one
// database it is not: the instance that processes the revocation drops its own
// entry, and every other instance keeps serving the old binding — with no expiry,
// forever. Disabling an account or changing a role therefore took effect on one
// instance and nowhere else, which is the shape of the bug ADR 0005 set out to
// fix, reappearing one layer up.
//
// A TTL is the floor guarantee rather than the whole answer. Publishing
// invalidations over Redis would cut the window to a round trip, but pub/sub is
// at-most-once: a dropped message or a Redis outage restores the unbounded
// staleness, so it can make revocation *faster* but cannot make it *certain*.
// The expiry does that on its own, with no broker to depend on. Thirty seconds
// keeps the database read rare while bounding how long a revoked session can
// outlive its revocation on a sibling instance.
const DefaultBindingTTL = 30 * time.Second

// BindingTTLEnv overrides DefaultBindingTTL, in seconds.
const BindingTTLEnv = "GATEON_SESSION_BINDING_TTL"

// bindingCache holds the current session binding per user id.
//
// Without it every authenticated request would cost a database round trip,
// which is a latency regression on the management API and a hard one on a
// two-core host. The map is keyed by the id inside an already-decrypted PASETO,
// so entries can only be created by a token this gateway itself minted — it is
// bounded by the number of real accounts, not by anything a caller can invent.
//
// Mutations invalidate rather than recompute: the next verify reloads from the
// database. That keeps the write path trivial and means a missed invalidation
// fails toward a database read rather than toward a stale allow.
type bindingCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]cachedBinding

	// now is injectable so the expiry tests do not sleep.
	now func() time.Time
}

type cachedBinding struct {
	binding string
	expires time.Time
}

func newBindingCache() *bindingCache {
	return newBindingCacheWithTTL(bindingTTLFromEnv())
}

func newBindingCacheWithTTL(ttl time.Duration) *bindingCache {
	if ttl <= 0 {
		ttl = DefaultBindingTTL
	}
	return &bindingCache{
		ttl:     ttl,
		entries: make(map[string]cachedBinding),
		now:     time.Now,
	}
}

func bindingTTLFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(BindingTTLEnv))
	if raw == "" {
		return DefaultBindingTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return DefaultBindingTTL
	}
	return time.Duration(secs) * time.Second
}

// get returns a cached binding only while it is still inside its TTL. An expired
// entry is reported as absent, so the caller reloads from the database — the
// same path a local invalidation takes.
func (c *bindingCache) get(id string) (string, bool) {
	c.mu.RLock()
	e, ok := c.entries[id]
	expired := ok && !c.now().Before(e.expires)
	c.mu.RUnlock()
	if !ok || expired {
		return "", false
	}
	return e.binding, true
}

func (c *bindingCache) put(id, binding string) {
	c.mu.Lock()
	c.entries[id] = cachedBinding{binding: binding, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

// invalidate drops one user's cached binding. Called on every mutation that
// changes a session-binding input. This is the immediate path on the instance
// that handled the mutation; siblings converge when their entry expires.
func (c *bindingCache) invalidate(id string) {
	c.mu.Lock()
	delete(c.entries, id)
	c.mu.Unlock()
}

// currentBinding returns the session binding for id as the database sees it
// now, using the cache when warm.
func (m *Manager) currentBinding(id string) (string, error) {
	if b, ok := m.bindings.get(id); ok {
		return b, nil
	}

	var (
		passwordHash string
		role         string
		disabled     bool
	)
	q := m.dialect.Rebind(QuerySessionBindingByID)
	if err := m.db.QueryRow(q, id).Scan(&passwordHash, &role, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Deleted account. Its tokens must stop working immediately.
			return "", ErrSessionRevoked
		}
		return "", err
	}
	if role == "" {
		role = RoleViewer
	}

	b := sessionBinding(passwordHash, role, disabled)
	m.bindings.put(id, b)
	return b, nil
}

// checkSessionBinding rejects a token whose binding no longer matches the
// account. An empty presented binding is refused too: tokens minted before this
// mechanism existed carry no binding and must not be grandfathered in, or the
// revocation check becomes optional for exactly the tokens issued while the
// gateway was vulnerable.
func (m *Manager) checkSessionBinding(id, presented string) error {
	if id == "" || presented == "" {
		return ErrSessionRevoked
	}
	current, err := m.currentBinding(id)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(current), []byte(presented)) != 1 {
		return ErrSessionRevoked
	}
	return nil
}
