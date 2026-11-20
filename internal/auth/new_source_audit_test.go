// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/audit"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var initAuditOnce sync.Once

// newSourceEntries puts a real audit log under this test binary, once, and
// collects the new-source entries stored for this test.
func newSourceEntries(t *testing.T) func() []audit.AuditEntry {
	t.Helper()
	initAuditOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gateon-auth-audit-*")
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Init(&gateonv1.AuditConfig{Enabled: true}, "sqlite:"+filepath.Join(dir, "audit.db")); err != nil {
			t.Fatal(err)
		}
	})
	var mu sync.Mutex
	var got []audit.AuditEntry
	remove := audit.AddSink(func(e audit.AuditEntry) {
		if e.Action != ActionLoginNewSource {
			return
		}
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	t.Cleanup(remove)
	return func() []audit.AuditEntry {
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.AuditEntry(nil), got...)
	}
}

// A password that works from a network the account has never signed in from
// is the earliest sign it was stolen, and nothing recorded it: the source was
// remembered for the lockout and nobody was told (ADR 0099). It is recorded
// once per network, so an owner's everyday sign-ins say nothing.
func TestAPasswordFromANewNetworkIsAudited(t *testing.T) {
	entries := newSourceEntries(t)
	m := newTestManager(t)
	createUser(t, m, "newsrc-admin", ownerPass)

	// The password step is what this is about; a second factor owed after it
	// is not a failure here.
	signIn := func(addr string) {
		t.Helper()
		_, _, err := m.Authenticate("newsrc-admin", ownerPass, addr)
		if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountLocked) || errors.Is(err, ErrBusy) {
			t.Fatalf("sign-in from %s: %v", addr, err)
		}
	}
	signIn("192.0.2.10:5000")
	signIn("192.0.2.11:5001") // same /24: the same network
	signIn("198.51.100.20:5002")

	got := entries()
	if len(got) != 2 {
		t.Fatalf("got %d new-source entries, want 2 (one per network): %+v", len(got), got)
	}
	if got[0].UserID != "newsrc-admin" || got[0].IPAddress != "192.0.2.10:5000" {
		t.Fatalf("first entry = %+v, want the account and the address it came from", got[0])
	}
	if got[1].IPAddress != "198.51.100.20:5002" {
		t.Fatalf("second entry = %+v, want the new network's address", got[1])
	}
}

// A wrong password is not a sign-in from anywhere.
func TestAWrongPasswordFromANewNetworkIsNotANewSource(t *testing.T) {
	entries := newSourceEntries(t)
	m := newTestManager(t)
	createUser(t, m, "newsrc-wrong", ownerPass)
	_, _, _ = m.Authenticate("newsrc-wrong", ownerPass+"x", "203.0.113.5:1")
	if got := entries(); len(got) != 0 {
		t.Fatalf("a refused password was recorded as a new source: %+v", got)
	}
}
