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
	full := bits / 8
	remBits := bits % 8

	for i := range full {
		b := ip[i]
		next, ok := curr.children[b]
		if !ok {
			next = newNode()
			curr.children[b] = next
		}
		curr = next
	}

	if remBits == 0 {
		curr.isEnd = true
		return
	}

	// A prefix that does not end on a byte boundary fixes only the top remBits
	// of the next byte; every value sharing those bits is inside the range. The
	// search walks bytes and compares them exactly, so each of those values
	// needs its own terminal child.
	//
	// This previously stored the masked byte alone -- one child for a range of
	// up to 128 -- so 10.16.0.0/12 matched only addresses whose second byte was
	// literally 0x10, a /12 covering a sixteenth of itself. Both callers were
	// hurt by that: internal/request holds the Cloudflare ranges here, almost
	// none of which are byte-aligned, and internal/middleware holds a deny tree,
	// where a rule that quietly stops denying is fail-open.
	//
	// Bounded at 2^(8-remBits) children, so at most 128 per inserted CIDR, and
	// only for the single byte where the prefix ends.
	mask := byte(0xFF) << (8 - remBits)
	base := ip[full] & mask
	for v := int(base); v <= int(base|^mask); v++ {
		b := byte(v)
		next, ok := curr.children[b]
		if !ok {
			next = newNode()
			curr.children[b] = next
		}
		// Marked rather than replaced: a longer prefix may already live here,
		// and this one is broader, so it must not lose its children.
		next.isEnd = true
	}
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
