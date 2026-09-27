// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"math"
	"slices"
	"sync"
	"time"
)

// The graph Graph Intelligence reads: which client classes (JA4+ values) the
// addresses caught attacking presented, and how much attack evidence each
// carries, recently.
//
// It used to link every address to its fingerprint, and to every path it
// requested, for good: sixteen shards of up to 5000 nodes with up to 1000
// neighbours each -- some eighty million entries' worth of ceiling on a 2 GB
// host -- copied whole on every analysis pass, and never decaying, so five
// visitors days apart made the same "cluster" as five at once. And a JA4+ value
// names a browser class, not a client (mem:reputation_identity): five people on
// one Chrome build share it. So only addresses with attack evidence are linked
// at all, a link fades with its evidence and is gone once it has gone unrenewed
// for attackLinkWindow, and both dimensions are capped.

const (
	// attackLinkHalfLife is how fast an unrenewed link's evidence fades.
	attackLinkHalfLife = 10 * time.Minute
	// attackLinkWindow is how long a link survives unrenewed.
	attackLinkWindow = 30 * time.Minute
	// maxAttackClasses and maxAttackLinksPerClass bound the store at 32768
	// links, a few megabytes. Only addresses with attack evidence are ever
	// linked, so reaching either needs that many attackers caught.
	maxAttackClasses       = 256
	maxAttackLinksPerClass = 128
)

// attackLink is one address's attack evidence under one client class.
type attackLink struct {
	evidence float64   // as of seen
	seen     time.Time // when the evidence was last renewed
}

// decayed is the link's evidence at now.
func (l attackLink) decayed(now time.Time) float64 {
	age := now.Sub(l.seen)
	if age <= 0 {
		return l.evidence
	}
	return l.evidence * math.Exp2(-age.Seconds()/attackLinkHalfLife.Seconds())
}

// attackClass is the addresses caught attacking behind one client class.
type attackClass struct {
	links  map[string]attackLink
	newest time.Time
}

// attackGraph is the store. One mutex: it is written once per analysis pass
// and per gossiped link, never on the request path.
type attackGraph struct {
	mu      sync.Mutex
	classes map[string]*attackClass
}

var globalAttackGraph = &attackGraph{classes: make(map[string]*attackClass)}

// ObserveAttackLink records that the address ip, presenting client class fp,
// carried evidence units of attack evidence as of at. The link keeps the larger
// of what it had, faded to at, and this, so an analysis pass re-reading the
// same threats renews a link without counting them twice.
func ObserveAttackLink(fp, ip string, evidence float64, at time.Time) {
	if fp == "" || ip == "" || !(evidence > 0) || math.IsInf(evidence, 0) {
		return
	}
	g := globalAttackGraph
	g.mu.Lock()
	defer g.mu.Unlock()
	class := g.classes[fp]
	if class == nil {
		g.makeRoomForClass()
		class = &attackClass{links: make(map[string]attackLink)}
		g.classes[fp] = class
	}
	link, known := class.links[ip]
	if !known {
		class.makeRoomForLink()
	}
	link.evidence = math.Max(link.decayed(at), evidence)
	if at.After(link.seen) {
		link.seen = at
	}
	class.links[ip] = link
	if at.After(class.newest) {
		class.newest = at
	}
}

// makeRoomForClass evicts the class renewed longest ago when the store is full.
func (g *attackGraph) makeRoomForClass() {
	if len(g.classes) < maxAttackClasses {
		return
	}
	var stalest string
	var stalestAt time.Time
	for fp, c := range g.classes {
		if stalest == "" || c.newest.Before(stalestAt) {
			stalest, stalestAt = fp, c.newest
		}
	}
	delete(g.classes, stalest)
}

// makeRoomForLink evicts the address renewed longest ago when the class is full.
func (c *attackClass) makeRoomForLink() {
	if len(c.links) < maxAttackLinksPerClass {
		return
	}
	var stalest string
	var stalestAt time.Time
	for ip, l := range c.links {
		if stalest == "" || l.seen.Before(stalestAt) {
			stalest, stalestAt = ip, l.seen
		}
	}
	delete(c.links, stalest)
}

// AttackCluster is one client class and the addresses behind it whose
// evidence, faded to the moment asked, still reaches the bar.
type AttackCluster struct {
	Fingerprint string
	Addresses   []string  // sorted
	Evidence    []float64 // index-aligned with Addresses
	Newest      time.Time // the most recent evidence among them
}

// AttackClusters returns every class with at least minAddresses addresses whose
// evidence at now is at least minEvidence. Links unrenewed for attackLinkWindow,
// and classes left empty, are dropped on the way; only what qualifies is copied.
func AttackClusters(now time.Time, minAddresses int, minEvidence float64) []AttackCluster {
	g := globalAttackGraph
	g.mu.Lock()
	defer g.mu.Unlock()
	var clusters []AttackCluster
	for fp, class := range g.classes {
		live := class.prune(now, minEvidence)
		if len(class.links) == 0 {
			delete(g.classes, fp)
			continue
		}
		if live < minAddresses {
			continue
		}
		clusters = append(clusters, class.cluster(fp, now, minEvidence, live))
	}
	slices.SortFunc(clusters, func(a, b AttackCluster) int { return b.Newest.Compare(a.Newest) })
	return clusters
}

// prune drops the class's expired links and counts those still at the bar.
func (c *attackClass) prune(now time.Time, minEvidence float64) int {
	live := 0
	for ip, l := range c.links {
		switch {
		case now.Sub(l.seen) > attackLinkWindow:
			delete(c.links, ip)
		case l.decayed(now) >= minEvidence:
			live++
		}
	}
	return live
}

// cluster copies the class's qualifying addresses.
func (c *attackClass) cluster(fp string, now time.Time, minEvidence float64, live int) AttackCluster {
	out := AttackCluster{Fingerprint: fp, Addresses: make([]string, 0, live)}
	for ip, l := range c.links {
		if l.decayed(now) >= minEvidence {
			out.Addresses = append(out.Addresses, ip)
			if l.seen.After(out.Newest) {
				out.Newest = l.seen
			}
		}
	}
	slices.Sort(out.Addresses)
	out.Evidence = make([]float64, len(out.Addresses))
	for i, ip := range out.Addresses {
		out.Evidence[i] = c.links[ip].decayed(now)
	}
	return out
}

// ResetAttackGraph forgets every link.
func ResetAttackGraph() {
	g := globalAttackGraph
	g.mu.Lock()
	defer g.mu.Unlock()
	clear(g.classes)
}

// attackGraphSize is how many classes and links the store holds.
func attackGraphSize() (classes, links int) {
	g := globalAttackGraph
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.classes {
		links += len(c.links)
	}
	return len(g.classes), links
}
