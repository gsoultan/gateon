// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package aiagent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
)

// The bounds on one list.
const (
	// maxListBytes is the most of one list that is read. The vendors' lists
	// are a few kilobytes; anything near this is not one.
	maxListBytes = 1 << 20
	// fetchTimeout covers the whole fetch, the body included.
	fetchTimeout = 30 * time.Second
	// minV4Bits and minV6Bits are the widest prefix a list may name. A crawler
	// fleet is a few hundred addresses; a list naming a /8 is wrong or
	// hostile, and in force it would let a whole network pass as the agent.
	minV4Bits = 16
	minV6Bits = 32
)

// errTooLarge is a list that would take the lists in force past their bound.
var errTooLarge = errors.New("the list would take the AI agent ranges past their bound")

// list is one parsed list: the prefixes it names, and how many entries it
// named too wide to keep.
type list struct {
	prefixes []netip.Prefix
	tooWide  int
}

// newClient is the client the lists are fetched with: each redirect is held
// to the same rule as the URL that was saved.
func newClient(rt http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return reputation.CheckFeedURL(req.URL.String())
		},
	}
}

// fetch reads one list. Anything but a 2xx answer is an error, not an empty
// list: taking an error page as the list would stop verifying the agent.
func fetch(ctx context.Context, client *http.Client, rawURL string, room int) (list, error) {
	if err := reputation.CheckFeedURL(rawURL); err != nil {
		return list{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return list{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return list{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return list{}, fmt.Errorf("answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return list{}, err
	}
	if len(body) > maxListBytes {
		return list{}, fmt.Errorf("is larger than %d bytes", maxListBytes)
	}
	return parse(body, room)
}

// rangeDocument is the shape OpenAI, Perplexity and Google publish theirs in.
type rangeDocument struct {
	Prefixes []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// parse reads a list as a range document when it is JSON, and as one address
// or CIDR per line, with "#" comments, otherwise. A list naming more than room
// prefixes is refused whole: half of a fleet's addresses would refuse the
// other half as fakes.
func parse(body []byte, room int) (list, error) {
	var l list
	add := func(s string) error {
		p, ok := parsePrefix(s)
		switch {
		case !ok:
			return nil
		case tooWide(p):
			l.tooWide++
			return nil
		case len(l.prefixes) >= room:
			return errTooLarge
		}
		l.prefixes = append(l.prefixes, p)
		return nil
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '{' {
		var doc rangeDocument
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return list{}, fmt.Errorf("is not a range document: %w", err)
		}
		for _, p := range doc.Prefixes {
			if err := add(p.IPv4 + p.IPv6); err != nil {
				return list{}, err
			}
		}
		return l, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if err := add(line); err != nil {
			return list{}, err
		}
	}
	return l, sc.Err()
}

// parsePrefix reads an address or a CIDR, masked, with an IPv4-mapped IPv6
// address read as the IPv4 address it maps.
func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if a := p.Addr(); a.Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), bits)
	}
	return p.Masked(), true
}

func tooWide(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < minV4Bits
	}
	return p.Bits() < minV6Bits
}
