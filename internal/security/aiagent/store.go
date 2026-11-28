// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package aiagent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MaxPrefixesEnv overrides the tier's bound on the prefixes in force.
const MaxPrefixesEnv = "GATEON_AI_AGENT_MAX_PREFIXES"

const (
	// maxSources is the most lists one configuration may name.
	maxSources = 32
	// refreshEvery is how often the lists are fetched again. Vendors change
	// theirs every few days at most.
	refreshEvery = 12 * time.Hour
)

// Verdict is what an address list says about a client that named an agent.
type Verdict uint8

const (
	// Unverifiable is a claim no list in force can judge: none is configured
	// for the agent, or none has loaded yet. A route treats the client like
	// any other.
	Unverifiable Verdict = iota
	// Verified is a client at an address its agent's vendor publishes.
	Verified
	// Spoofed is a client that named an agent whose lists are in force, from
	// an address none of them names.
	Spoofed
)

// Source is one configured list.
type Source struct{ Agent, URL string }

// index is the lists in force, by agent. It is never changed once published.
type index map[string][]netip.Prefix

// Store holds the lists in force. Verify is safe for concurrent use and
// takes no lock; one goroutine, Run, fetches.
type Store struct {
	idx    atomic.Pointer[index]
	kick   chan struct{}
	client *http.Client
	limit  int

	mu       sync.Mutex
	sources  []Source
	lastGood map[Source][]netip.Prefix // goroutine-owned once Run starts
}

// New returns a store whose lists may hold limit prefixes in all.
func New(limit int, rt http.RoundTripper) *Store {
	s := &Store{kick: make(chan struct{}, 1), client: newClient(rt), limit: limit,
		lastGood: make(map[Source][]netip.Prefix)}
	s.idx.Store(&index{})
	return s
}

// Limit is the tier's bound, or MaxPrefixesEnv's when that is a positive
// integer.
func Limit() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(MaxPrefixesEnv))); err == nil && n > 0 {
		return n
	}
	return config.CurrentTierDefaults().AIAgentMaxPrefixes
}

// Shared is the process's one store.
var Shared = sync.OnceValue(func() *Store { return New(Limit(), http.DefaultTransport) })

// SourcesOf reads the configured lists from the global settings.
func SourcesOf(cfg *gateonv1.BotManagementConfig) []Source {
	var out []Source
	for _, r := range cfg.GetAiAgentRanges() {
		out = append(out, Source{Agent: strings.TrimSpace(r.GetAgent()), URL: strings.TrimSpace(r.GetUrl())})
	}
	return out
}

// Configure sets the lists to keep in force. A change is fetched at once;
// the lists in force stay until the fetch replaces them.
func (s *Store) Configure(sources []Source) {
	s.mu.Lock()
	changed := !slices.Equal(s.sources, sources)
	s.sources = slices.Clone(sources)
	s.mu.Unlock()
	if changed {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// Run fetches the lists when they change and every refreshEvery, until ctx
// is done.
func (s *Store) Run(ctx context.Context) {
	tick := time.NewTicker(refreshEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
		case <-tick.C:
		}
		s.Refresh(ctx)
	}
}

// Refresh fetches every configured list once and puts the result in force. A
// list that fails keeps its last good copy, so a vendor's outage does not
// make its real crawler a fake. Run calls it; a test may call it instead.
func (s *Store) Refresh(ctx context.Context) {
	s.mu.Lock()
	sources := slices.Clone(s.sources)
	s.mu.Unlock()

	next := index{}
	kept := make(map[Source][]netip.Prefix, len(sources))
	missing := map[string]bool{}
	room := s.limit
	for _, src := range sources {
		prefixes, err := s.load(ctx, src, room)
		if err != nil {
			logger.L.LogWarn("an AI agent range list could not be loaded; its last good copy stays in force",
				"agent", src.Agent, "url", src.URL, "error", err)
		}
		if len(prefixes) > room {
			prefixes = nil
		}
		if prefixes == nil {
			missing[src.Agent] = true
			continue
		}
		kept[src] = prefixes
		next[src.Agent] = append(next[src.Agent], prefixes...)
		room -= len(prefixes)
	}
	// An agent with a list that has nothing in force is judged by none of
	// them: the addresses that list would have named would read as fakes.
	for agent := range missing {
		delete(next, agent)
	}
	s.lastGood = kept
	s.idx.Store(&next)
}

func (s *Store) load(ctx context.Context, src Source, room int) ([]netip.Prefix, error) {
	l, err := fetch(ctx, s.client, src.URL, room)
	if err != nil {
		return s.lastGood[src], err
	}
	if l.tooWide > 0 {
		logger.L.LogWarn("an AI agent range list names prefixes too wide to be a crawler's; they were left out",
			"agent", src.Agent, "url", src.URL, "left_out", l.tooWide)
	}
	if len(l.prefixes) == 0 {
		// An empty list verifies nobody, so every real crawler would read as
		// a fake. It is an error, like an error page.
		return s.lastGood[src], errors.New("the list names no addresses")
	}
	return l.prefixes, nil
}

// Verify reports what the lists in force say about a client at addr that
// named agent. It takes no lock and allocates nothing.
func (s *Store) Verify(agent string, addr netip.Addr) Verdict {
	if s == nil {
		return Unverifiable
	}
	prefixes, ok := (*s.idx.Load())[agent]
	if !ok || !addr.IsValid() {
		return Unverifiable
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return Verified
		}
	}
	return Spoofed
}

// Loaded is how many prefixes are in force for each agent that has any.
func (s *Store) Loaded() map[string]int {
	out := map[string]int{}
	for agent, p := range *s.idx.Load() {
		out[agent] = len(p)
	}
	return out
}

// ValidateSources refuses, at save, a configuration the gateway would not
// act on: an agent outside the catalog, a URL it would not fetch, more lists
// than it keeps. A URL already stored is not judged again, as for the IP
// feeds, so one stored before a rule does not block an unrelated save.
func ValidateSources(stored, proposed []*gateonv1.AIAgentRangeSource) error {
	if len(proposed) > maxSources {
		return fmt.Errorf("at most %d AI agent range lists may be configured, not %d", maxSources, len(proposed))
	}
	known := make(map[string]bool, len(stored))
	for _, s := range stored {
		known[strings.TrimSpace(s.GetUrl())] = true
	}
	for _, p := range proposed {
		agent, u := strings.TrimSpace(p.GetAgent()), strings.TrimSpace(p.GetUrl())
		if !Known(agent) {
			return fmt.Errorf("AI agent range list %q names agent %q, which is not one the gateway recognises", u, agent)
		}
		if known[u] {
			continue
		}
		if err := reputation.CheckFeedURL(u); err != nil {
			return fmt.Errorf("the address list for %s: %w", agent, err)
		}
	}
	return nil
}
