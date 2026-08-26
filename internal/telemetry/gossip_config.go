// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"crypto/sha256"
	"errors"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// defaultGossipPort is memberlist's conventional port, kept as the default so
// existing single-node deployments do not move.
const defaultGossipPort = 7946

// errGossipNoAuthPass is returned when gossip is asked to run without a shared
// secret. Gossip messages are applied directly to IP reputation, which decides
// whether a client is shunned, so an unauthenticated cluster lets anyone who can
// reach the port choose who gets blocked.
var errGossipNoAuthPass = errors.New(
	"ha.auth_pass is empty: gossip would accept reputation updates from anyone able to reach the port")

// gossipSettings is the resolved, validated transport configuration.
type gossipSettings struct {
	BindAddr  string
	BindPort  int
	Peers     []string
	SecretKey []byte
}

// gossipEnabled reports whether the gossip transport should run at all.
//
// This now honours enable_gossip, which the implementation previously ignored:
// it keyed off HaConfig.Enabled alone, so switching on VIP failover silently
// opened an unauthenticated port that had nothing to do with failover.
func gossipEnabled(conf *gateonv1.HaConfig) bool {
	return conf != nil && conf.GetEnabled() && conf.GetEnableGossip()
}

// gossipSecretKey derives memberlist's symmetric key from the HA auth pass.
//
// memberlist requires exactly 16, 24 or 32 bytes, while auth_pass is a free-form
// operator-chosen string, so it is hashed rather than truncated or padded —
// truncating would silently discard entropy from a long passphrase and padding
// would make short ones weaker than they look. SHA-256 gives the 32 bytes that
// select AES-256.
func gossipSecretKey(authPass string) []byte {
	sum := sha256.Sum256([]byte(authPass))
	return sum[:]
}

// resolveGossipSettings validates the config and works out where to bind.
//
// ifaceIP is the IPv4 address of HaConfig.Interface, resolved by the caller so
// this stays a pure function of its inputs. Precedence is explicit-config, then
// the HA interface, then memberlist's own default — an operator who names a bind
// address means it, even when an interface is also configured.
func resolveGossipSettings(conf *gateonv1.HaConfig, ifaceIP string) (gossipSettings, error) {
	if conf == nil {
		return gossipSettings{}, errGossipNoAuthPass
	}
	if strings.TrimSpace(conf.GetAuthPass()) == "" {
		return gossipSettings{}, errGossipNoAuthPass
	}

	s := gossipSettings{
		BindPort:  defaultGossipPort,
		SecretKey: gossipSecretKey(conf.GetAuthPass()),
	}

	if addr := strings.TrimSpace(conf.GetGossipBindAddr()); addr != "" {
		s.BindAddr = addr
	} else if ifaceIP != "" {
		s.BindAddr = ifaceIP
	}

	if port := conf.GetGossipBindPort(); port > 0 && port <= 65535 {
		s.BindPort = int(port)
	}

	// Blank entries would make memberlist attempt a dial to "" and report a
	// confusing error, so they are dropped here rather than at the call site.
	for _, p := range conf.GetGossipPeers() {
		if p = strings.TrimSpace(p); p != "" {
			s.Peers = append(s.Peers, p)
		}
	}

	return s, nil
}
