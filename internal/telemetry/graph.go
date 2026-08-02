// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package telemetry

import (
	"hash/fnv"
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
	h.Write([]byte(u))
	idx := h.Sum32() % graphShards

	shards := getGlobalGraph()
	s := shards[idx]
	s.mu.Lock()
	if s.edges[u] == nil {
		s.edges[u] = make(map[string]float64)
	}
	s.edges[u][v] += weight

	// Basic LRU-like pruning: if a node has too many neighbors, trim the weakest ones
	if len(s.edges[u]) > 1000 {
		for k := range s.edges[u] {
			if s.edges[u][k] < 2.0 {
				delete(s.edges[u], k)
			}
			if len(s.edges[u]) <= 800 {
				break
			}
		}
	}
	s.mu.Unlock()
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
