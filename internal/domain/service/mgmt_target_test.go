// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/mgmtaddr"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSaveRefusesATargetOnTheManagementListener (ADR 0052, review finding
// MGMT-N2): a service pointed at the gateway's own management port on a local
// address, behind a Host() route on a public entrypoint, served the dashboard,
// sign-in and API to the internet from loopback. The save is refused naming
// the target, and nothing is stored -- also when the target is one of several.
func TestSaveRefusesATargetOnTheManagementListener(t *testing.T) {
	prev := mgmtaddr.Register(18734)
	t.Cleanup(func() { mgmtaddr.Register(prev) })
	for _, target := range []string{
		"http://127.0.0.1:18734", "http://[::1]:18734", "http://0.0.0.0:18734",
		"http://localhost:18734", "h2c://127.0.0.1:18734", "tcp://127.0.0.1:18734", "127.0.0.1:18734",
	} {
		store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
		s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		err := s.SaveService(t.Context(), &gateonv1.Service{Id: "loop", WeightedTargets: []*gateonv1.Target{
			{Url: "http://192.0.2.10:8080", Weight: 1}, {Url: target, Weight: 1},
		}})
		if !errors.Is(err, ErrInvalidService) || !strings.Contains(err.Error(), target) ||
			!strings.Contains(err.Error(), "management listener") {
			t.Errorf("save with target %s: err = %v, want ErrInvalidService naming it and the management listener", target, err)
		}
		if len(store.services) != 0 {
			t.Errorf("a service targeting %s was stored", target)
		}
	}
}

// TestSaveKeepsATargetThatDoesNotReachTheManagementListener: another port on
// loopback, the management port's number on another host, and a UDP service
// (the listener is TCP only) all save.
func TestSaveKeepsATargetThatDoesNotReachTheManagementListener(t *testing.T) {
	prev := mgmtaddr.Register(18734)
	t.Cleanup(func() { mgmtaddr.Register(prev) })
	for _, svc := range []*gateonv1.Service{
		{WeightedTargets: []*gateonv1.Target{{Url: "http://127.0.0.1:18735", Weight: 1}}},
		{WeightedTargets: []*gateonv1.Target{{Url: "http://192.0.2.10:18734", Weight: 1}}},
		{BackendType: "udp", WeightedTargets: []*gateonv1.Target{{Url: "127.0.0.1:18734", Weight: 1}}},
	} {
		s := NewService(&fakeServiceStore{services: map[string]*gateonv1.Service{}},
			&fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		if err := s.SaveService(t.Context(), svc); err != nil {
			t.Errorf("%v refused: %v", svc, err)
		}
	}
}
