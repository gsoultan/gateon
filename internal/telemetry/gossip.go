// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/hashicorp/memberlist"
)

// ReputationDelegate implements memberlist.Delegate for broadcasting reputation updates.
//
// Its queue is memberlist's own TransmitLimitedQueue. It used to be a plain
// slice that GetBroadcasts handed over whole and emptied, and memberlist asks
// once per node it gossips to in a round, so every update reached the first
// node asked and no other: in a cluster of three or more, a penalty or an
// operator's release reached one random peer and nothing retransmitted it. The
// whole slice went out whatever limit memberlist offered, too, so a burst under
// attack left as datagrams far past the path MTU and was lost after the queue
// had been emptied. The transmit-limited queue retransmits each update to a
// number of nodes that grows with the cluster, and never hands out more than
// fits.
//
// The zero value is usable; startGossip attaches the member list so the
// retransmit count follows the cluster's size.
type ReputationDelegate struct {
	queueOnce      sync.Once
	queue          *memberlist.TransmitLimitedQueue
	retransmitMult int
	list           atomic.Pointer[memberlist.Memberlist]
}

// maxQueuedGossipUpdates bounds the queue: past it the oldest updates are
// dropped. Updates arrive at the rate threats are recorded, which an attacker
// sets, and gossip drains a packet's worth per node per round.
const maxQueuedGossipUpdates = 1000

// defaultGossipRetransmitMult is memberlist's LAN default, for a delegate built
// without a configuration.
const defaultGossipRetransmitMult = 4

// broadcasts returns the delegate's queue, building it on first use.
func (d *ReputationDelegate) broadcasts() *memberlist.TransmitLimitedQueue {
	d.queueOnce.Do(func() {
		mult := d.retransmitMult
		if mult <= 0 {
			mult = defaultGossipRetransmitMult
		}
		d.queue = &memberlist.TransmitLimitedQueue{NumNodes: d.numNodes, RetransmitMult: mult}
	})
	return d.queue
}

// numNodes is the cluster size the retransmit count is computed from.
func (d *ReputationDelegate) numNodes() int {
	if list := d.list.Load(); list != nil {
		return list.NumMembers()
	}
	return 1
}

// gossipUpdate is one queued message. A named one -- a reputation update, named
// by the identity it scores -- replaces a queued update for the same identity,
// since peers only need the latest score; an unnamed one replaces nothing.
type gossipUpdate struct {
	name string
	msg  []byte
}

func (u *gossipUpdate) Invalidates(other memberlist.Broadcast) bool {
	o, ok := other.(*gossipUpdate)
	return ok && u.name != "" && o.name == u.name
}

func (u *gossipUpdate) Message() []byte { return u.msg }
func (u *gossipUpdate) Finished()       {}

// enqueue queues msg under name, keeping the queue bounded.
func (d *ReputationDelegate) enqueue(name string, msg []byte) {
	q := d.broadcasts()
	q.QueueBroadcast(&gossipUpdate{name: name, msg: msg})
	if q.NumQueued() > maxQueuedGossipUpdates {
		q.Prune(maxQueuedGossipUpdates)
	}
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
			applyRemoteAttackLink(&payload, time.Now())
		}
	}
}

// Graph Intelligence's gossip. A peer sends the attack links it observed --
// address, client class, evidence -- and a node files them as it files its own
// (ObserveAttackLink), so a campaign spread across gateways forms one cluster.
//
// It used to send every address's fingerprint as an ip -> fp edge, and the
// detector read fp -> ip, so nothing a peer sent ever reached a detection. Peers
// on that release still send those, as type "fp_ip" with no evidence behind
// them; they are ignored, since counting them would bring back the
// browser-class clusters the store exists to avoid.
const (
	attackLinkEdgeType    = "attack_evidence"
	attackClassNodePrefix = "fp:"
	// maxRemoteAttackEvidence caps what one gossiped link may claim, so a
	// peer's arithmetic cannot outweigh every local observation.
	maxRemoteAttackEvidence = 100.0
)

// BroadcastAttackLink gossips one attack link to the cluster, when gossip runs.
func BroadcastAttackLink(fp, ip string, evidence float64) {
	if gossipManager == nil {
		return
	}
	data, err := json.Marshal(&gateonv1.GraphEdgeSyncPayload{
		SourceNode: ip,
		TargetNode: attackClassNodePrefix + fp,
		Weight:     evidence,
		Type:       attackLinkEdgeType,
	})
	if err != nil {
		return
	}
	// Named by the link, so a newer measure replaces one still queued rather
	// than queueing behind it.
	gossipManager.delegate.enqueue("graph|"+fp+"|"+ip, data)
}

// applyRemoteAttackLink files a peer's attack link, as observed at at.
func applyRemoteAttackLink(p *gateonv1.GraphEdgeSyncPayload, at time.Time) {
	fp, isClass := strings.CutPrefix(p.GetTargetNode(), attackClassNodePrefix)
	if p.GetType() != attackLinkEdgeType || !isClass || net.ParseIP(p.GetSourceNode()) == nil {
		return
	}
	ObserveAttackLink(fp, p.GetSourceNode(), math.Min(p.GetWeight(), maxRemoteAttackEvidence), at)
}

func (d *ReputationDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.broadcasts().GetBroadcasts(overhead, limit)
}

func (d *ReputationDelegate) LocalState(join bool) []byte {
	return nil
}

func (d *ReputationDelegate) MergeRemoteState(buf []byte, join bool) {
}

// Enqueue queues a message that no later message replaces.
func (d *ReputationDelegate) Enqueue(msg []byte) {
	d.enqueue("", msg)
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
	mconf := memberlist.DefaultLANConfig()
	delegate := &ReputationDelegate{retransmitMult: mconf.RetransmitMult}
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
	delegate.list.Store(list)

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

	// Named by the identity, so a newer score replaces one still queued.
	gossipManager.delegate.enqueue(fingerprint, data)
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
