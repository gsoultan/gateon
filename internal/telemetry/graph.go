// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"cmp"
	"hash/fnv"
	"slices"
	"sync"
)

const graphShards = 16

type graphShard struct {
	mu    sync.RWMutex
	edges map[string]map[string]float64 // NodeID -> NeighborID -> Weight
}

var (
	globalGraph     [graphShards]*graphShard
	globalGraphOnce sync.Once
)

func getGlobalGraph() [graphShards]*graphShard {
	globalGraphOnce.Do(func() {
		for i := 0; i < graphShards; i++ {
			globalGraph[i] = &graphShard{
				edges: make(map[string]map[string]float64),
			}
		}
	})
	return globalGraph
}

// AddGraphEdge adds a weighted edge to the global sharded graph.
func AddGraphEdge(u, v string, weight float64) {
	if u == "" || v == "" {
		return
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(u))
	idx := h.Sum32() % graphShards

	shards := getGlobalGraph()
	s := shards[idx]
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.edges[u] == nil {
		// Global node limit per shard to ensure 2GB RAM stability
		if len(s.edges) >= 5000 {
			// Evict a few random nodes to make room (simple scavenging)
			evicted := 0
			for k := range s.edges {
				delete(s.edges, k)
				evicted++
				if evicted >= 100 {
					break
				}
			}
		}
		s.edges[u] = make(map[string]float64)
	}
	s.edges[u][v] += weight

	// A node's neighbor set is bounded by dropping its weakest edges. The
	// previous trim only deleted edges below 2.0, and both kinds of edge the
	// detector adds reach that weight -- fingerprint edges start there, path
	// edges get there on their second pass -- so a node whose neighbors were all
	// "strong" was never trimmed at all and grew with every pass.
	if len(s.edges[u]) > maxGraphNeighbors {
		trimWeakestNeighbors(s.edges[u], graphNeighborsKeep)
	}
}

const (
	// maxGraphNeighbors is the most neighbors one node may hold before it is
	// trimmed; graphNeighborsKeep is what a trim leaves, so trimming is not
	// repeated on every insert once the cap is reached.
	maxGraphNeighbors  = 1000
	graphNeighborsKeep = 800
)

// trimWeakestNeighbors deletes the lowest-weight neighbors until keep remain.
func trimWeakestNeighbors(neighbors map[string]float64, keep int) {
	if keep < 0 || len(neighbors) <= keep {
		return
	}
	type edge struct {
		id     string
		weight float64
	}
	all := make([]edge, 0, len(neighbors))
	for id, w := range neighbors {
		all = append(all, edge{id: id, weight: w})
	}
	slices.SortFunc(all, func(a, b edge) int { return cmp.Compare(a.weight, b.weight) })
	for _, e := range all[:len(all)-keep] {
		delete(neighbors, e.id)
	}
}

// GetGraphSnapshot returns a copy of the graph for analysis.
func GetGraphSnapshot() map[string]map[string]float64 {
	shards := getGlobalGraph()
	snapshot := make(map[string]map[string]float64)
	for i := 0; i < graphShards; i++ {
		s := shards[i]
		s.mu.RLock()
		for u, neighbors := range s.edges {
			snapshot[u] = make(map[string]float64)
			for v, w := range neighbors {
				snapshot[u][v] = w
			}
		}
		s.mu.RUnlock()
	}
	return snapshot
}
