// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/hashicorp/memberlist"
)

// recordingPeer is a cluster member that keeps every user message it receives,
// so a test can tell which node an update reached. It stands in for another
// gateway: the production delegate applies what arrives to this process's own
// reputation store, which every node in one test process would share.
type recordingPeer struct {
	msgs chan []byte
}

func (p *recordingPeer) NodeMeta(int) []byte { return nil }
func (p *recordingPeer) NotifyMsg(b []byte) {
	select {
	case p.msgs <- bytes.Clone(b):
	default:
	}
}
func (p *recordingPeer) GetBroadcasts(int, int) [][]byte { return nil }
func (p *recordingPeer) LocalState(bool) []byte          { return nil }
func (p *recordingPeer) MergeRemoteState([]byte, bool)   {}

// waitFor reports whether a message containing marker reaches p within d.
func (p *recordingPeer) waitFor(marker string, d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case m := <-p.msgs:
			if bytes.Contains(m, []byte(marker)) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

const fanoutTestPass = "gossip-fanout-test"

// startGossipNode starts this gateway's gossip exactly as InitGossip does, on a
// loopback port of its own, and tears it down with the test.
func startGossipNode(t *testing.T) *memberlist.Memberlist {
	t.Helper()
	settings := gossipSettings{BindAddr: "127.0.0.1", SecretKey: gossipSecretKey(fanoutTestPass)}
	if err := startGossip(&gateonv1.HaConfig{}, settings); err != nil {
		t.Fatalf("startGossip: %v", err)
	}
	list := gossipManager.list
	t.Cleanup(func() {
		_ = list.Shutdown()
		gossipManager = nil
	})
	return list
}

// joinRecordingPeer starts a peer with the same key and joins it to seed.
func joinRecordingPeer(t *testing.T, name string, seed *memberlist.Memberlist) *recordingPeer {
	t.Helper()
	peer := &recordingPeer{msgs: make(chan []byte, 256)}
	conf := memberlist.DefaultLANConfig()
	conf.Name = name
	conf.BindAddr = "127.0.0.1"
	conf.BindPort = 0
	conf.SecretKey = gossipSecretKey(fanoutTestPass)
	conf.Delegate = peer
	conf.LogOutput = io.Discard
	list, err := memberlist.Create(conf)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { _ = list.Shutdown() })
	if _, err := list.Join([]string{seed.LocalNode().Address()}); err != nil {
		t.Fatalf("%s join: %v", name, err)
	}
	return peer
}

// awaitMembers waits until list sees n members.
func awaitMembers(t *testing.T, list *memberlist.Memberlist, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for list.NumMembers() < n {
		if time.Now().After(deadline) {
			t.Fatalf("setup: cluster has %d members, want %d", list.NumMembers(), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReputationUpdatesReachEveryPeer is the regression test for gossip that
// told one node and nobody else.
//
// memberlist asks the delegate for broadcasts once per node it gossips to in a
// round. GetBroadcasts handed its whole queue to the first caller and emptied
// it, and nothing retransmits a user message, so every update -- a penalty, and
// an operator's release, which is broadcast as a reset to 100 -- reached one
// random peer. In a two-node pair that is the other node; in anything larger
// the rest of the cluster kept refusing the address the operator had just
// released, and kept serving the one another node had just caught.
func TestReputationUpdatesReachEveryPeer(t *testing.T) {
	self := startGossipNode(t)
	peers := map[string]*recordingPeer{
		"peer-b": joinRecordingPeer(t, "peer-b", self),
		"peer-c": joinRecordingPeer(t, "peer-c", self),
	}
	awaitMembers(t, self, 3)

	for _, update := range []struct {
		what  string
		send  func(fp string)
		score float64
	}{
		{"a penalty", func(fp string) { BroadcastReputation(fp, 12, 3, []string{"waf_blocked"}) }, 12},
		{"a release", func(fp string) { BroadcastReputation(fp, 100, 0, []string{"Manual reset"}) }, 100},
	} {
		fp := "fanout-" + strings.ReplaceAll(update.what, " ", "-") + "|203.0.113"
		update.send(fp)
		for name, peer := range peers {
			if !peer.waitFor(fp, 5*time.Second) {
				t.Errorf("%s (score %v) for %s never reached %s: gossip delivered it "+
					"to one peer of %d", update.what, update.score, fp, name, len(peers))
			}
		}
	}
}

// TestGossipBroadcastsFitTheSpaceOffered pins the delegate's side of
// memberlist's contract: GetBroadcasts is told how many bytes a packet has room
// for, and must not return more.
//
// It returned its whole queue -- up to a thousand updates -- whatever limit it
// was given. memberlist packs what it is handed into compound UDP packets of up
// to 255 messages each, so a burst of penalties under attack went out as
// datagrams far past the path MTU, fragmenting where fragments are dropped and
// failing outright past 64 KiB, after the queue had already been emptied: the
// updates were lost with nothing retrying them.
func TestGossipBroadcastsFitTheSpaceOffered(t *testing.T) {
	const overhead, limit = 2, 1400
	d := &ReputationDelegate{}
	for i := range 300 {
		queueLikeBroadcast(d, fmt.Sprintf("burst-%03d|198.51.100", i))
	}

	var total int
	for _, msg := range d.GetBroadcasts(overhead, limit) {
		total += len(msg) + overhead
	}
	if total > limit {
		t.Fatalf("GetBroadcasts returned %d bytes for a packet with room for %d", total, limit)
	}
	if total == 0 {
		t.Fatal("GetBroadcasts returned nothing with 300 updates queued")
	}
}

// TestANewerScoreReplacesAQueuedOne: peers only need an identity's latest
// score, so a second update for the same identity must replace the first
// rather than queue behind it. Under attack the same few identities are
// penalised over and over, and a queue that kept every intermediate score
// spent its bounded space and its packets on values already superseded.
func TestANewerScoreReplacesAQueuedOne(t *testing.T) {
	d := &ReputationDelegate{}
	prev := gossipManager
	gossipManager = &GossipManager{delegate: d}
	t.Cleanup(func() { gossipManager = prev })

	const fp = "replaced|203.0.113"
	BroadcastReputation(fp, 40, 1, []string{"waf_blocked"})
	BroadcastReputation(fp, 100, 0, []string{"Manual reset"})

	var sent []string
	for _, msg := range d.GetBroadcasts(2, 64*1024) {
		sent = append(sent, string(msg))
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "Manual reset") {
		t.Fatalf("queued for %s: %q, want only the latest update (the reset)", fp, sent)
	}
}

// queueLikeBroadcast queues on d the payload BroadcastReputation would send for
// fp, through the delegate's public Enqueue.
func queueLikeBroadcast(d *ReputationDelegate, fp string) {
	msg := fmt.Sprintf(`{"fingerprint":%q,"score":12,"violation_count":3,"history":["waf_blocked","rate_limit"]}`, fp)
	d.Enqueue([]byte(msg))
}
