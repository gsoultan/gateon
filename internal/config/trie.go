// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"cmp"
	"slices"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// trieNode represents a single segment in the path trie.
type trieNode struct {
	children map[string]*trieNode
	exact    []*gateonv1.Route
	prefix   []*gateonv1.Route

	// Pre-calculated flattened lists for O(1) candidate retrieval.
	// allPrefix stores all prefix routes from this node and its ancestors.
	// allExact stores all routes in allPrefix plus the exact routes at this node.
	allPrefix []*gateonv1.Route
	allExact  []*gateonv1.Route
}

// PathTrie is a Radix-like tree optimized for HTTP path matching.
// It supports both exact path matching and prefix matching.
type PathTrie struct {
	root *trieNode
}

func NewPathTrie() *PathTrie {
	return &PathTrie{
		root: &trieNode{
			children: make(map[string]*trieNode),
		},
	}
}

// Insert adds a route to the trie. path should be the path or path prefix from the rule.
func (t *PathTrie) Insert(path string, isPrefix bool, rt *gateonv1.Route) {
	path = strings.Trim(path, "/")
	curr := t.root
	if path != "" {
		parts := strings.Split(path, "/")
		for _, part := range parts {
			if part == "" {
				continue
			}
			if curr.children[part] == nil {
				curr.children[part] = &trieNode{
					children: make(map[string]*trieNode),
				}
			}
			curr = curr.children[part]
		}
	}

	if isPrefix {
		curr.prefix = append(curr.prefix, rt)
	} else {
		curr.exact = append(curr.exact, rt)
	}
}

// Flatten pre-calculates the allPrefix and allExact slices for all nodes.
// It should be called once after all routes have been inserted.
// It inherits prefixes from ancestors to avoid O(depth) lookup complexity.
func (t *PathTrie) Flatten() {
	flattenNode(t.root, nil)
}

func flattenNode(curr *trieNode, inheritedPrefixes []*gateonv1.Route) {
	// allPrefix = inherited from parent + prefixes at this node
	curr.allPrefix = make([]*gateonv1.Route, 0, len(inheritedPrefixes)+len(curr.prefix))
	curr.allPrefix = append(curr.allPrefix, inheritedPrefixes...)
	curr.allPrefix = append(curr.allPrefix, curr.prefix...)

	// Sort by priority and specificity (longer rule = more specific)
	sortRoutes(curr.allPrefix)

	// allExact = allPrefix + exact routes at this node
	curr.allExact = make([]*gateonv1.Route, 0, len(curr.allPrefix)+len(curr.exact))
	curr.allExact = append(curr.allExact, curr.allPrefix...)
	curr.allExact = append(curr.allExact, curr.exact...)
	sortRoutes(curr.allExact)

	for _, child := range curr.children {
		flattenNode(child, curr.allPrefix)
	}
}

func sortRoutes(routes []*gateonv1.Route) {
	if len(routes) <= 1 {
		return
	}
	// Note: In trie context, specificity (len(Rule)) is mostly handled by the trie depth,
	// but we still include it for consistency with SelectRouteFromSlice.
	slices.SortFunc(routes, func(a, b *gateonv1.Route) int {
		if a.Priority != b.Priority {
			return cmp.Compare(b.Priority, a.Priority)
		}
		if len(a.Rule) != len(b.Rule) {
			return cmp.Compare(len(b.Rule), len(a.Rule))
		}
		return strings.Compare(a.Id, b.Id)
	})
}

// Lookup returns all routes that could match the given path.
// It returns a pre-sorted slice of candidates.
func (t *PathTrie) Lookup(path string) []*gateonv1.Route {
	path = strings.Trim(path, "/")
	curr := t.root

	if path == "" {
		return curr.allExact
	}

	parts := strings.Split(path, "/")
	lastNode := curr
	for _, part := range parts {
		if part == "" {
			continue
		}
		next := curr.children[part]
		if next == nil {
			// We stop here; only prefix matches from this node and ancestors apply.
			return curr.allPrefix
		}
		curr = next
		lastNode = curr
	}

	// We matched the path exactly to a node.
	return lastNode.allExact
}
