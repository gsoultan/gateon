// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
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
	entries map[string]string
}

func newBindingCache() *bindingCache {
	return &bindingCache{entries: make(map[string]string)}
}

func (c *bindingCache) get(id string) (string, bool) {
	c.mu.RLock()
	v, ok := c.entries[id]
	c.mu.RUnlock()
	return v, ok
}

func (c *bindingCache) put(id, binding string) {
	c.mu.Lock()
	c.entries[id] = binding
	c.mu.Unlock()
}

// invalidate drops one user's cached binding. Called on every mutation that
// changes a session-binding input.
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
