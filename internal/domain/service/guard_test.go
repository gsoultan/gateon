// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeServiceGuard struct {
	err    error
	called bool
	saw    *gateonv1.Service
}

func (g *fakeServiceGuard) AuthorizeServiceSave(_ context.Context, svc *gateonv1.Service) error {
	g.called = true
	g.saw = svc
	return g.err
}

// A SaveGuard authorizes a service save before it persists; a refusal stores
// nothing. It runs after the id is assigned, so it sees the service it will save.
func TestSaveServiceRefusedByTheGuardStoresNothing(t *testing.T) {
	store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
	guard := &fakeServiceGuard{err: errors.New("needs an administrator")}
	s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil, guard)

	err := s.SaveService(context.Background(), &gateonv1.Service{})
	if err == nil || !errors.Is(err, guard.err) {
		t.Fatalf("SaveService error = %v, want the guard's refusal", err)
	}
	if !guard.called {
		t.Error("the guard was not consulted")
	}
	if len(store.services) != 0 {
		t.Error("a service the guard refused was stored")
	}
}

func TestSaveServiceAllowedByTheGuardIsStored(t *testing.T) {
	store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
	guard := &fakeServiceGuard{}
	s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil, guard)

	svc := &gateonv1.Service{}
	if err := s.SaveService(context.Background(), svc); err != nil {
		t.Fatalf("SaveService: %v", err)
	}
	if !guard.called || guard.saw == nil || guard.saw.Id == "" {
		t.Errorf("the guard saw %+v, want the service with its id assigned", guard.saw)
	}
	if len(store.services) != 1 {
		t.Error("an allowed service was not stored")
	}
}
