// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"bytes"
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestGossipRefusesToRunWithoutASharedSecret is the regression guard for the
// defect: memberlist was created with no SecretKey, so anything that reached the
// port was accepted and applied to IP reputation, which decides who gets shunned.
func TestGossipRefusesToRunWithoutASharedSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf *gateonv1.HaConfig
	}{
		{"nil config", nil},
		{"no auth pass", &gateonv1.HaConfig{Enabled: true, EnableGossip: true}},
		{"whitespace auth pass", &gateonv1.HaConfig{Enabled: true, EnableGossip: true, AuthPass: "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveGossipSettings(tc.conf, ""); !errors.Is(err, errGossipNoAuthPass) {
				t.Fatalf("got %v, want errGossipNoAuthPass", err)
			}
		})
	}
}

// enable_gossip was ignored: gossip keyed off HaConfig.Enabled, so turning on
// VIP failover silently opened an unauthenticated port unrelated to failover.
func TestEnableGossipActuallyGatesGossip(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf *gateonv1.HaConfig
		want bool
	}{
		{"nil", nil, false},
		{"all off", &gateonv1.HaConfig{}, false},
		{"ha on, gossip not requested", &gateonv1.HaConfig{Enabled: true}, false},
		{"gossip requested but ha off", &gateonv1.HaConfig{EnableGossip: true}, false},
		{"both on", &gateonv1.HaConfig{Enabled: true, EnableGossip: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gossipEnabled(tc.conf); got != tc.want {
				t.Fatalf("gossipEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGossipSecretKeyIsMemberlistSized(t *testing.T) {
	key := gossipSecretKey("correct horse battery staple")
	// memberlist accepts 16, 24 or 32 bytes; 32 selects AES-256.
	if len(key) != 32 {
		t.Fatalf("key is %d bytes, want 32", len(key))
	}
	if bytes.Equal(key, gossipSecretKey("a different pass")) {
		t.Error("different auth passes produced the same key")
	}
	if !bytes.Equal(key, gossipSecretKey("correct horse battery staple")) {
		t.Error("key derivation is not deterministic; peers would never agree")
	}
	// A long passphrase must not be silently truncated to its first 32 bytes.
	long := "this passphrase is definitely longer than thirty-two bytes in total"
	if bytes.Equal(gossipSecretKey(long), gossipSecretKey(long[:32])) {
		t.Error("long passphrase was truncated, discarding entropy")
	}
}

// The bind address and port were hardcoded and the configured peers were never
// contacted, so none of these fields did anything.
func TestResolveGossipSettingsHonoursTheConfiguredFields(t *testing.T) {
	conf := &gateonv1.HaConfig{
		Enabled: true, EnableGossip: true, AuthPass: "secret",
		GossipBindAddr: "10.0.0.5", GossipBindPort: 9999,
		GossipPeers: []string{"10.0.0.6:9999", "  ", "10.0.0.7:9999"},
	}
	got, err := resolveGossipSettings(conf, "192.168.1.1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// An explicit bind address wins over the HA interface's address.
	if got.BindAddr != "10.0.0.5" {
		t.Errorf("BindAddr = %q, want the explicitly configured 10.0.0.5", got.BindAddr)
	}
	if got.BindPort != 9999 {
		t.Errorf("BindPort = %d, want 9999", got.BindPort)
	}
	if len(got.Peers) != 2 {
		t.Errorf("Peers = %v, want the two non-blank entries", got.Peers)
	}
}

func TestResolveGossipSettingsFallsBackSensibly(t *testing.T) {
	conf := &gateonv1.HaConfig{Enabled: true, EnableGossip: true, AuthPass: "secret"}

	got, err := resolveGossipSettings(conf, "192.168.1.1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.BindAddr != "192.168.1.1" {
		t.Errorf("BindAddr = %q, want the HA interface address", got.BindAddr)
	}
	if got.BindPort != defaultGossipPort {
		t.Errorf("BindPort = %d, want the %d default", got.BindPort, defaultGossipPort)
	}

	// No interface either: leave it to memberlist rather than guessing.
	bare, err := resolveGossipSettings(conf, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if bare.BindAddr != "" {
		t.Errorf("BindAddr = %q, want empty so memberlist chooses", bare.BindAddr)
	}
}

// An out-of-range port must fall back rather than be handed to memberlist.
func TestResolveGossipSettingsRejectsAnImpossiblePort(t *testing.T) {
	for _, port := range []int32{-1, 0, 65536, 999999} {
		conf := &gateonv1.HaConfig{
			Enabled: true, EnableGossip: true, AuthPass: "secret", GossipBindPort: port,
		}
		got, err := resolveGossipSettings(conf, "")
		if err != nil {
			t.Fatalf("port %d: resolve: %v", port, err)
		}
		if got.BindPort != defaultGossipPort {
			t.Errorf("port %d: BindPort = %d, want the %d default", port, got.BindPort, defaultGossipPort)
		}
	}
}
