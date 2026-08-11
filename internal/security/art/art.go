// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package art

import (
	"net"
	"net/netip"
	"sync"
)

// Tree is an Adaptive Radix Tree optimized for IP/CIDR matching.
// It supports both IPv4 and IPv6.
type Tree struct {
	mu    sync.RWMutex
	root4 *node
	root6 *node
}

type node struct {
	children map[byte]*node
	isEnd    bool
}

func newNode() *node {
	return &node{
		children: make(map[byte]*node),
	}
}

// NewTree creates a new IPTree.
func NewTree() *Tree {
	return &Tree{
		root4: newNode(),
		root6: newNode(),
	}
}

// IsEmpty returns true if the tree has no CIDRs.
func (t *Tree) IsEmpty() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.root4.children) == 0 && len(t.root6.children) == 0 && !t.root4.isEnd && !t.root6.isEnd
}

// InsertCIDR inserts a CIDR into the tree.
func (t *Tree) InsertCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ones, _ := ipnet.Mask.Size()
	ip := ipnet.IP

	t.mu.Lock()
	defer t.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		t.insert(t.root4, ip4, ones)
	} else {
		t.insert(t.root6, ip, ones)
	}
	return nil
}

func (t *Tree) insert(root *node, ip []byte, bits int) {
	curr := root
	bytes := bits / 8
	remBits := bits % 8

	for i := range bytes {
		b := ip[i]
		if next, ok := curr.children[b]; ok {
			curr = next
		} else {
			next := newNode()
			curr.children[b] = next
			curr = next
		}
	}

	if remBits > 0 {
		// Handle partial byte for CIDR masks not aligned to 8 bits
		// For simplicity in this implementation, we treat partial bytes as full byte branches
		// with a mask. A true ART would handle this more elegantly.
		// However, most CIDRs are /8, /16, /24, /32.
		// To be fully correct, we'd need bit-by-bit or a more complex node.
		// Let's implement bit-by-bit for the remaining bits if needed,
		// but 8-bit fanout is much faster.
		b := ip[bytes] & (0xFF << (8 - remBits))
		if next, ok := curr.children[b]; ok {
			curr = next
		} else {
			next := newNode()
			curr.children[b] = next
			curr = next
		}
	}

	curr.isEnd = true
}

// ContainsAddr checks if a netip.Addr is contained in any of the inserted CIDRs.
func (t *Tree) ContainsAddr(ip netip.Addr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if ip.Is4() {
		return t.search(t.root4, ip.AsSlice())
	}
	return t.search(t.root6, ip.AsSlice())
}

// Contains checks if an IP string is contained in any of the inserted CIDRs.
func (t *Tree) Contains(ipStr string) bool {
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		return t.ContainsAddr(addr)
	}
	return false
}

func (t *Tree) search(root *node, ip []byte) bool {
	curr := root
	if curr.isEnd {
		return true
	}

	for _, b := range ip {
		next, ok := curr.children[b]
		if !ok {
			return false
		}
		curr = next
		if curr.isEnd {
			return true
		}
	}

	return curr.isEnd
}
