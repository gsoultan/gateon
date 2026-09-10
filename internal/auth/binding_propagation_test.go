// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"sync"
	"testing"
)

// A revocation used to reach only the instance that handled the mutation;
// every sibling served the old binding until its entry expired. These pin the
// propagation that closes that, and — more importantly — the two properties
// that make propagating over an at-most-once broker safe: the remote path can
// only invalidate, and it never echoes.
//
// See ADR 0012.

type recordingPublisher struct {
	mu  sync.Mutex
	ids []string
}

func (p *recordingPublisher) PublishBindingRevocation(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids = append(p.ids, id)
}

func (p *recordingPublisher) published() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.ids...)
}

func TestRevokeSessions_PublishesToPeers(t *testing.T) {
	m := newTestManager(t)
	pub := &recordingPublisher{}
	m.SetBindingPublisher(pub)

	m.revokeSessions("user-1")

	got := pub.published()
	if len(got) != 1 || got[0] != "user-1" {
		t.Fatalf("expected one publish for user-1, got %v", got)
	}
}

// The loop guard. If InvalidateBinding published, two instances would bounce a
// single revocation between each other for as long as both stayed up.
func TestInvalidateBinding_DoesNotPublish(t *testing.T) {
	m := newTestManager(t)
	pub := &recordingPublisher{}
	m.SetBindingPublisher(pub)

	m.InvalidateBinding("user-1")

	if got := pub.published(); len(got) != 0 {
		t.Fatalf("applying a remote invalidation must not re-publish it, got %v", got)
	}
}

// The security property, stated as a test so it fails if the remote path ever
// gains the ability to populate. A message may remove a cached binding; it may
// not create or change one, so the worst it can do is force a database read.
func TestInvalidateBinding_CannotPopulateTheCache(t *testing.T) {
	m := newTestManager(t)

	m.InvalidateBinding("never-seen")

	if _, ok := m.bindings.get("never-seen"); ok {
		t.Fatal("a remote invalidation created a cache entry; it must only ever delete one")
	}
}

func TestRevokeSessions_InvalidatesLocallyBeforePublishing(t *testing.T) {
	m := newTestManager(t)
	m.bindings.put("user-1", "stale")

	var seenDuringPublish bool
	m.SetBindingPublisher(publisherFunc(func(string) {
		_, seenDuringPublish = m.bindings.get("user-1")
	}))

	m.revokeSessions("user-1")

	if seenDuringPublish {
		t.Fatal("the local entry must be gone before peers are told; " +
			"a publish that blocks or fails would otherwise leave this instance stale")
	}
}

// No publisher is the default and every single-instance deployment. It must be
// silent, not a panic on the revocation path.
func TestRevokeSessions_NoPublisherIsSafe(t *testing.T) {
	m := newTestManager(t)
	m.bindings.put("user-1", "stale")

	m.revokeSessions("user-1")

	if _, ok := m.bindings.get("user-1"); ok {
		t.Fatal("local invalidation must still happen with no publisher installed")
	}
}

func TestSetBindingPublisher_NilDisablesPropagation(t *testing.T) {
	m := newTestManager(t)
	pub := &recordingPublisher{}
	m.SetBindingPublisher(pub)
	m.SetBindingPublisher(nil)

	m.revokeSessions("user-1")

	if got := pub.published(); len(got) != 0 {
		t.Fatalf("a nil publisher must stop propagation, got %v", got)
	}
}

// The first-run case, and the one this nearly shipped broken. The publisher is
// installed at startup, when a fresh install has no Manager at all; Setup builds
// one later. If the Holder did not re-apply, propagation would silently never
// start on exactly those installs.
func TestHolder_AppliesPublisherToAServiceInstalledLater(t *testing.T) {
	h := NewHolder(nil)
	pub := &recordingPublisher{}
	h.SetBindingPublisher(pub)

	m := newTestManager(t)
	h.Set(m) // what Setup does

	m.revokeSessions("user-1")

	got := pub.published()
	if len(got) != 1 || got[0] != "user-1" {
		t.Fatalf("publisher was not applied to the service Setup installed, got %v", got)
	}
}

func TestHolder_AppliesPublisherToTheCurrentService(t *testing.T) {
	m := newTestManager(t)
	h := NewHolder(m)
	pub := &recordingPublisher{}
	h.SetBindingPublisher(pub)

	m.revokeSessions("user-2")

	got := pub.published()
	if len(got) != 1 || got[0] != "user-2" {
		t.Fatalf("publisher was not applied to the installed service, got %v", got)
	}
}

func TestHolder_InvalidateBindingWithNoServiceIsSafe(t *testing.T) {
	NewHolder(nil).InvalidateBinding("user-1") // must not panic
}

type publisherFunc func(string)

func (f publisherFunc) PublishBindingRevocation(id string) { f(id) }
