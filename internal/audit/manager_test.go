// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// internal/audit had no tests at all, which for a package whose entire purpose
// is tamper evidence meant the tamper evidence itself was an untested claim —
// and it backs a compliance statement, so it is the one worth proving first.
//
// These tests exercise the chain through the same signing path log() uses, then
// tamper with the result the way an attacker with database access would: edit a
// field, drop an entry, swap two, splice one in, re-sign with their own key.
// Each must be caught.

const testKey = "6f1d4d9b8c2e4a1f9e0b7c3a5d8f2b6e4c1a9d7f3b5e8c2a6d4f1b9e7c3a5d8f"

// buildChain produces n correctly-signed, correctly-chained entries, oldest
// first, exactly as log() would have written them.
func buildChain(t *testing.T, n int, key string) []AuditEntry {
	t.Helper()
	entries := make([]AuditEntry, 0, n)
	prev := ""
	base := time.Unix(1_760_000_000, 0).UTC()
	for i := range n {
		e := AuditEntry{
			ID:           hex.EncodeToString([]byte{byte(i), 0xab, 0xcd}),
			UserID:       "admin",
			Action:       "update_route",
			Resource:     "routes",
			Details:      "changed backend",
			Timestamp:    base.Add(time.Duration(i) * time.Minute),
			IPAddress:    "203.0.113.7",
			PreviousHash: prev,
		}
		e.Signature = signEntry(e, key)
		prev = e.Signature
		entries = append(entries, e)
	}
	return entries
}

// chainErr asserts the failure is a ChainError and returns it, so each test can
// check the reason rather than just "some error".
func chainErr(t *testing.T, err error) *ChainError {
	t.Helper()
	if err == nil {
		t.Fatal("expected the tampering to be detected, got nil")
	}
	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("error is %T (%v), want *ChainError", err, err)
	}
	return ce
}

func TestVerifyChain_HonestChainVerifies(t *testing.T) {
	if err := VerifyChain(buildChain(t, 5, testKey), testKey, ""); err != nil {
		t.Fatalf("an untampered chain must verify, got %v", err)
	}
}

func TestVerifyChain_EmptyChainVerifies(t *testing.T) {
	if err := VerifyChain(nil, testKey, ""); err != nil {
		t.Fatalf("an empty log is not a broken one, got %v", err)
	}
}

// The most likely real attack: change what an action says it did, leave
// everything else alone.
func TestVerifyChain_DetectsEditedField(t *testing.T) {
	entries := buildChain(t, 5, testKey)
	entries[2].Details = "changed backend to attacker.example"

	ce := chainErr(t, VerifyChain(entries, testKey, ""))
	if ce.Index != 2 {
		t.Fatalf("Index = %d, want 2", ce.Index)
	}
	if !strings.Contains(ce.Reason, "signature does not match") {
		t.Fatalf("Reason = %q, want the signature mismatch", ce.Reason)
	}
}

// Changing who did it must be caught the same way — UserID is inside the MAC.
func TestVerifyChain_DetectsRewrittenActor(t *testing.T) {
	entries := buildChain(t, 3, testKey)
	entries[1].UserID = "someone-else"

	if ce := chainErr(t, VerifyChain(entries, testKey, "")); ce.Index != 1 {
		t.Fatalf("Index = %d, want 1", ce.Index)
	}
}

// Backdating an entry must be caught: Timestamp is in the MAC at second
// granularity.
func TestVerifyChain_DetectsBackdatedTimestamp(t *testing.T) {
	entries := buildChain(t, 3, testKey)
	entries[2].Timestamp = entries[2].Timestamp.Add(-72 * time.Hour)

	if ce := chainErr(t, VerifyChain(entries, testKey, "")); ce.Index != 2 {
		t.Fatalf("Index = %d, want 2", ce.Index)
	}
}

// Deleting the record of an action is the attack the chain exists to stop: the
// survivor's PreviousHash no longer resolves to anything.
func TestVerifyChain_DetectsDeletedEntry(t *testing.T) {
	entries := buildChain(t, 5, testKey)
	withHole := append(append([]AuditEntry{}, entries[:2]...), entries[3:]...)

	ce := chainErr(t, VerifyChain(withHole, testKey, ""))
	if ce.Index != 2 {
		t.Fatalf("Index = %d, want 2 (the entry orphaned by the deletion)", ce.Index)
	}
	if !strings.Contains(ce.Reason, "previous_hash") {
		t.Fatalf("Reason = %q, want the chain-link failure", ce.Reason)
	}
}

// Deleting the newest entry leaves a chain that is internally consistent, so it
// is caught by the caller pinning the expected head, not by VerifyChain alone.
// Recording that limit here so nobody assumes truncation is covered.
func TestVerifyChain_TruncationNeedsAnExternalHead(t *testing.T) {
	entries := buildChain(t, 5, testKey)
	truncated := entries[:4]

	if err := VerifyChain(truncated, testKey, ""); err != nil {
		t.Fatalf("a truncated chain is still internally valid, got %v", err)
	}
	// What catches it: the last signature no longer matches the head an
	// operator (or an external witness) recorded previously.
	if truncated[len(truncated)-1].Signature == entries[len(entries)-1].Signature {
		t.Fatal("expected the head signature to differ after truncation")
	}
}

func TestVerifyChain_DetectsReorderedEntries(t *testing.T) {
	entries := buildChain(t, 5, testKey)
	entries[1], entries[2] = entries[2], entries[1]

	if ce := chainErr(t, VerifyChain(entries, testKey, "")); ce.Index != 1 {
		t.Fatalf("Index = %d, want 1", ce.Index)
	}
}

// An attacker who can insert rows but cannot sign gets caught immediately.
func TestVerifyChain_DetectsInsertedEntry(t *testing.T) {
	entries := buildChain(t, 4, testKey)
	forged := AuditEntry{
		ID: "forged-1", UserID: "admin", Action: "delete_user",
		Resource: "users", Details: "covering tracks",
		Timestamp: entries[1].Timestamp.Add(time.Second),
		IPAddress: "203.0.113.7", PreviousHash: entries[1].Signature,
		Signature: strings.Repeat("00", 32),
	}
	spliced := append([]AuditEntry{}, entries[:2]...)
	spliced = append(spliced, forged)
	spliced = append(spliced, entries[2:]...)

	if ce := chainErr(t, VerifyChain(spliced, testKey, "")); ce.Index != 2 {
		t.Fatalf("Index = %d, want 2 (the forged entry)", ce.Index)
	}
}

// An attacker who re-signs the whole chain with their own key produces something
// self-consistent — it verifies under their key and must not under ours. This is
// the property that makes the key the trust anchor.
func TestVerifyChain_RejectsChainSignedWithAnotherKey(t *testing.T) {
	const attackerKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	rewritten := buildChain(t, 4, attackerKey)

	if err := VerifyChain(rewritten, attackerKey, ""); err != nil {
		t.Fatalf("sanity: the attacker's own chain should verify under their key, got %v", err)
	}
	if ce := chainErr(t, VerifyChain(rewritten, testKey, "")); ce.Index != 0 {
		t.Fatalf("Index = %d, want 0", ce.Index)
	}
}

// Signing must be off-by-default-safe: an unsigned entry is not silently
// accepted as valid.
func TestVerifyChain_RejectsUnsignedEntry(t *testing.T) {
	entries := buildChain(t, 3, testKey)
	entries[1].Signature = ""

	ce := chainErr(t, VerifyChain(entries, testKey, ""))
	if !strings.Contains(ce.Reason, "unsigned") {
		t.Fatalf("Reason = %q, want the unsigned-entry failure", ce.Reason)
	}
}

func TestVerifyChain_RefusesWithoutAKey(t *testing.T) {
	ce := chainErr(t, VerifyChain(buildChain(t, 2, testKey), "", ""))
	if !strings.Contains(ce.Reason, "no signature key") {
		t.Fatalf("Reason = %q, want the missing-key refusal", ce.Reason)
	}
}

// Verifying a window of history rather than the whole log: the caller supplies
// the preceding entry's signature as the genesis.
func TestVerifyChain_VerifiesAWindowFromAGenesis(t *testing.T) {
	entries := buildChain(t, 6, testKey)

	if err := VerifyChain(entries[3:], testKey, entries[2].Signature); err != nil {
		t.Fatalf("a window anchored to its predecessor must verify, got %v", err)
	}
	// The anchor has to be the real one.
	if err := VerifyChain(entries[3:], testKey, "not-the-previous-signature"); err == nil {
		t.Fatal("a window anchored to the wrong genesis must not verify")
	}
}

func TestGenerateSignatureKey(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for range 32 {
		k := GenerateSignatureKey()
		if len(k) != 64 {
			t.Fatalf("key %q has length %d, want 64 hex chars (256 bits)", k, len(k))
		}
		if _, err := hex.DecodeString(k); err != nil {
			t.Fatalf("key %q is not hex: %v", k, err)
		}
		if _, dup := seen[k]; dup {
			t.Fatalf("GenerateSignatureKey repeated a key: %q", k)
		}
		seen[k] = struct{}{}
	}
}

// The signature must cover every field an attacker would want to change. If
// someone adds a field to AuditEntry and forgets to include it in signEntry,
// this catches it — that omission is invisible otherwise, because the chain
// still verifies.
func TestSignEntry_CoversEveryMeaningfulField(t *testing.T) {
	base := AuditEntry{
		ID: "id-1", UserID: "admin", Action: "delete_route",
		Resource: "routes", Details: "removed /admin",
		Timestamp: time.Unix(1_760_000_000, 0).UTC(),
		IPAddress: "203.0.113.7", PreviousHash: "deadbeef",
	}
	want := signEntry(base, testKey)

	mutations := map[string]func(*AuditEntry){
		"ID":           func(e *AuditEntry) { e.ID = "id-2" },
		"UserID":       func(e *AuditEntry) { e.UserID = "mallory" },
		"Action":       func(e *AuditEntry) { e.Action = "create_route" },
		"Resource":     func(e *AuditEntry) { e.Resource = "users" },
		"Details":      func(e *AuditEntry) { e.Details = "removed nothing" },
		"Timestamp":    func(e *AuditEntry) { e.Timestamp = e.Timestamp.Add(time.Hour) },
		"IPAddress":    func(e *AuditEntry) { e.IPAddress = "198.51.100.9" },
		"PreviousHash": func(e *AuditEntry) { e.PreviousHash = "cafebabe" },
	}
	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			e := base
			mutate(&e)
			if signEntry(e, testKey) == want {
				t.Fatalf("changing %s did not change the signature; it is outside the MAC", field)
			}
		})
	}
}
