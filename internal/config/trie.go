package config

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"strings"
)

// trieNode represents a single segment in the path trie.
type trieNode struct {
	children map[string]*trieNode
	exact    []*gateonv1.Route
	prefix   []*gateonv1.Route
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

// Lookup returns all routes that could match the given path.
// The results are not sorted; the caller should sort them by priority.
// It returns routes that match as a prefix of the given path, or an exact match.
func (t *PathTrie) Lookup(path string) []*gateonv1.Route {
	path = strings.Trim(path, "/")
	var candidates []*gateonv1.Route
	curr := t.root

	// Root matches (e.g. PathPrefix("/"))
	candidates = append(candidates, curr.prefix...)
	if path == "" {
		candidates = append(candidates, curr.exact...)
		return candidates
	}

	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next := curr.children[part]
		if next == nil {
			break
		}
		curr = next

		// If this is the last part of the search path, it can be an exact match
		if i == len(parts)-1 {
			candidates = append(candidates, curr.exact...)
		}
		// Any node along the path can be a prefix match for the search path
		candidates = append(candidates, curr.prefix...)
	}

	return candidates
}
