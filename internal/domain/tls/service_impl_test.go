// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"context"
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeTLSStore struct {
	config.TLSOptionStore
	saved     map[string]*gateonv1.TLSOption
	deleted   []string
	updateErr error
	deleteErr error
}

func newFakeTLSStore() *fakeTLSStore {
	return &fakeTLSStore{saved: map[string]*gateonv1.TLSOption{}}
}
func (f *fakeTLSStore) Update(_ context.Context, o *gateonv1.TLSOption) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.saved[o.Id] = o
	return nil
}
func (f *fakeTLSStore) Delete(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

type countingInvalidator struct{ tls int }

func (c *countingInvalidator) InvalidateRoute(string)                      {}
func (c *countingInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (c *countingInvalidator) InvalidateTLS()                              { c.tls++ }
func (c *countingInvalidator) InvalidateWAF()                              {}

// TestSaveTLSOptionAssignsAnIDAndInvalidates covers the create path.
//
// The invalidation is the point. TLS options are compiled into the listener's
// config, so an option saved without invalidating is one that does not take
// effect until a restart — an operator tightening a cipher suite would believe
// it applied while the old one kept negotiating.
func TestSaveTLSOptionAssignsAnIDAndInvalidates(t *testing.T) {
	store, inv := newFakeTLSStore(), &countingInvalidator{}
	s := NewService(store, inv, nil)

	opt := &gateonv1.TLSOption{MinTlsVersion: "TLS1.3"}
	if err := s.SaveTLSOption(context.Background(), opt); err != nil {
		t.Fatalf("SaveTLSOption: %v", err)
	}
	if opt.Id == "" {
		t.Error("no id was assigned; the next save would create a second option")
	}
	if inv.tls != 1 {
		t.Errorf("InvalidateTLS called %d times, want 1 — a saved TLS option that "+
			"does not reach the listener is a setting the operator believes is "+
			"applied and is not", inv.tls)
	}
}

// TestSaveTLSOptionKeepsAnExistingID covers the edit path.
func TestSaveTLSOptionKeepsAnExistingID(t *testing.T) {
	s := NewService(newFakeTLSStore(), &countingInvalidator{}, nil)

	opt := &gateonv1.TLSOption{Id: "modern", MinTlsVersion: "TLS1.3"}
	if err := s.SaveTLSOption(context.Background(), opt); err != nil {
		t.Fatalf("SaveTLSOption: %v", err)
	}
	if opt.Id != "modern" {
		t.Errorf("id became %q; an edit must update the option, not fork it", opt.Id)
	}
}

// TestSaveTLSOptionDoesNotInvalidateWhenTheStoreFails pins the ordering.
//
// Rebuilding every listener's TLS config after a write that did not happen is
// churn on the whole gateway caused by an edit that was rejected.
func TestSaveTLSOptionDoesNotInvalidateWhenTheStoreFails(t *testing.T) {
	store, inv := newFakeTLSStore(), &countingInvalidator{}
	store.updateErr = errors.New("disk full")

	if err := NewService(store, inv, nil).SaveTLSOption(context.Background(),
		&gateonv1.TLSOption{Id: "modern"}); err == nil {
		t.Fatal("a failed store write was reported as success")
	}
	if inv.tls != 0 {
		t.Errorf("InvalidateTLS was called %d times after the write failed", inv.tls)
	}
}

// TestDeleteTLSOptionInvalidates covers the delete path.
func TestDeleteTLSOptionInvalidates(t *testing.T) {
	store, inv := newFakeTLSStore(), &countingInvalidator{}
	s := NewService(store, inv, nil)

	if err := s.DeleteTLSOption(context.Background(), "modern"); err != nil {
		t.Fatalf("DeleteTLSOption: %v", err)
	}
	if len(store.deleted) != 1 {
		t.Error("the option was not deleted")
	}
	if inv.tls != 1 {
		t.Errorf("InvalidateTLS called %d times, want 1 — a deleted option that "+
			"stays compiled into the listener is still negotiating", inv.tls)
	}
}

// TestDeleteTLSOptionRefusesAnEmptyID and does not invalidate on failure.
func TestDeleteTLSOptionRefusesAnEmptyID(t *testing.T) {
	store, inv := newFakeTLSStore(), &countingInvalidator{}
	s := NewService(store, inv, nil)

	if err := s.DeleteTLSOption(context.Background(), ""); err == nil {
		t.Error("an empty id was accepted")
	}
	if len(store.deleted) != 0 || inv.tls != 0 {
		t.Errorf("deleted %v / invalidated %d times on an empty id", store.deleted, inv.tls)
	}

	store.deleteErr = errors.New("nope")
	if err := s.DeleteTLSOption(context.Background(), "modern"); err == nil {
		t.Error("a failed delete was reported as success")
	}
	if inv.tls != 0 {
		t.Errorf("InvalidateTLS was called %d times after the delete failed", inv.tls)
	}
}
