// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/hashicorp/memberlist"
)

// ReputationDelegate implements memberlist.Delegate for broadcasting reputation updates.
type ReputationDelegate struct {
	mu       sync.Mutex
	messages [][]byte
}

func (d *ReputationDelegate) NodeMeta(limit int) []byte {
	return nil
}

func (d *ReputationDelegate) NotifyMsg(msg []byte) {
	// Identify payload type by unmarshaling to a map first or trying both
	var raw map[string]interface{}
	if err := json.Unmarshal(msg, &raw); err != nil {
		return
	}

	if _, ok := raw["fingerprint"]; ok {
		var payload gateonv1.ReputationSyncPayload
		if err := json.Unmarshal(msg, &payload); err == nil {
			// Apply the received reputation update locally.
			ApplyRemoteReputation(payload.Fingerprint, payload.Score, int(payload.ViolationCount), payload.History)
		}
	} else if _, ok := raw["source_node"]; ok {
		var payload gateonv1.GraphEdgeSyncPayload
		if err := json.Unmarshal(msg, &payload); err == nil {
			AddGraphEdge(payload.SourceNode, payload.TargetNode, payload.Weight)
		}
	}
}

func BroadcastGraphEdge(u, v string, weight float64, edgeType string) {
	if gossipManager == nil {
		return
	}

	payload := &gateonv1.GraphEdgeSyncPayload{
		SourceNode: u,
		TargetNode: v,
		Weight:     weight,
		Type:       edgeType,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	gossipManager.delegate.Enqueue(data)
}

func (d *ReputationDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.messages) == 0 {
		return nil
	}

	res := d.messages
	d.messages = nil
	return res
}

func (d *ReputationDelegate) LocalState(join bool) []byte {
	return nil
}

func (d *ReputationDelegate) MergeRemoteState(buf []byte, join bool) {
}

func (d *ReputationDelegate) Enqueue(msg []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Limit queue size to avoid memory exhaustion under heavy attack.
	if len(d.messages) > 1000 {
		d.messages = d.messages[1:]
	}
	d.messages = append(d.messages, msg)
}

var (
	gossipManager *GossipManager
	gossipOnce    sync.Once
)

type GossipManager struct {
	list     *memberlist.Memberlist
	delegate *ReputationDelegate
	conf     *gateonv1.HaConfig
}

func InitGossip(conf *gateonv1.HaConfig) error {
	if !gossipEnabled(conf) {
		return nil
	}

	settings, err := resolveGossipSettings(conf, interfaceIPv4(conf.GetInterface()))
	if err != nil {
		// Fail closed. Arriving gossip is applied straight to IP reputation, and
		// a score below the shun threshold blocks the client, so an
		// unauthenticated cluster hands anyone who can reach the port the ability
		// to choose which addresses this gateway refuses.
		return fmt.Errorf("refusing to start gossip: %w", err)
	}

	gossipOnce.Do(func() {
		err = startGossip(conf, settings)
	})
	return err
}

// interfaceIPv4 returns the first non-loopback IPv4 address on the named
// interface, or "" when the interface is unnamed, missing or has none.
func interfaceIPv4(name string) string {
	if name == "" {
		return ""
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// startGossip creates the memberlist and joins the configured peers.
func startGossip(conf *gateonv1.HaConfig, settings gossipSettings) error {
	delegate := &ReputationDelegate{}
	mconf := memberlist.DefaultLANConfig()
	mconf.Delegate = delegate
	mconf.BindPort = settings.BindPort
	mconf.AdvertisePort = settings.BindPort
	mconf.Name = fmt.Sprintf("gateon-%d", time.Now().UnixNano())
	if settings.BindAddr != "" {
		mconf.BindAddr = settings.BindAddr
	}
	// Authenticates and encrypts every message. Without it memberlist accepts
	// anything that reaches the port, and NotifyMsg applies it to reputation.
	mconf.SecretKey = settings.SecretKey

	list, err := memberlist.Create(mconf)
	if err != nil {
		return err
	}

	gossipManager = &GossipManager{
		list:     list,
		delegate: delegate,
		conf:     conf,
	}

	logger.L.LogInfo("Gossip reputation sync initialized",
		"node", mconf.Name, "bind", mconf.BindAddr, "port", mconf.BindPort, "encrypted", true)

	joinGossipPeers(list, settings.Peers)
	return nil
}

// joinGossipPeers contacts the configured peers once.
//
// One attempt is enough and is the ordinary memberlist pattern: the cluster
// converges as soon as any single node reaches any other, so a node that boots
// before its peers is picked up when one of them starts and joins inward. A
// retry loop would need a lifecycle this function does not have — InitGossip is
// boot-only with no stop hook — and an unsupervised goroutine is worse than the
// gap it would close.
func joinGossipPeers(list *memberlist.Memberlist, peers []string) {
	if len(peers) == 0 {
		logger.L.LogInfo("No gossip peers configured; waiting to be joined")
		return
	}
	reached, err := list.Join(peers)
	if err != nil && reached == 0 {
		logger.L.LogError("Could not reach any gossip peer; reputation will not sync until one joins",
			"peers", peers, "error", err)
		return
	}
	logger.L.LogInfo("Joined gossip cluster", "reached", reached, "configured", len(peers))
}

func BroadcastReputation(fingerprint string, score float64, violations int, history []string) {
	if gossipManager == nil {
		return
	}

	payload := &gateonv1.ReputationSyncPayload{
		Fingerprint:    fingerprint,
		Score:          score,
		ViolationCount: int32(violations),
		History:        history,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	gossipManager.delegate.Enqueue(data)
}

func GetGossipStatus() *gateonv1.GossipStatus {
	if gossipManager == nil {
		return &gateonv1.GossipStatus{Enabled: false}
	}

	members := gossipManager.list.Members()
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}

	return &gateonv1.GossipStatus{
		Enabled:      true,
		MembersCount: int32(len(members)),
		MemberNames:  names,
	}
}
