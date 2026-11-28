// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package aiagent knows the AI crawlers and agents by the name they give, and
// checks that a client giving one of those names comes from an address its
// vendor publishes (ADR 0108).
//
// A User-Agent is the client's own word. "GPTBot" in it proves nothing, and
// scrapers write it because sites that welcome a model's crawler wave it
// through. What the vendors do publish is the addresses their crawlers use.
// The operator lists where each list lives; the gateway fetches them in the
// background, bounded like its IP feeds (ADR 0061), and a route decides what
// a claim it cannot back up costs.
package aiagent

import "strings"

// Class is what an agent fetches for.
type Class uint8

const (
	// Training crawls pages to train a model.
	Training Class = iota + 1
	// Search crawls pages for an AI search index.
	Search
	// User fetches a page because a person asked an assistant to, now.
	User
)

func (c Class) String() string {
	switch c {
	case Training:
		return "training"
	case Search:
		return "search"
	case User:
		return "user"
	default:
		return "unknown"
	}
}

// Agent is one AI agent the gateway recognises.
type Agent struct {
	// Name is the token the agent writes in its User-Agent, exactly.
	Name   string
	Vendor string
	Class  Class
}

// The vendors with more than one agent.
const (
	vendorOpenAI     = "OpenAI"
	vendorAnthropic  = "Anthropic"
	vendorPerplexity = "Perplexity"
)

// catalog is every agent the gateway recognises, by the token its vendor
// documents. Matched as written: a client that writes the token otherwise is
// not claiming to be the agent, and costs nothing to tell apart.
var catalog = [...]Agent{
	{Name: "GPTBot", Vendor: vendorOpenAI, Class: Training},
	{Name: "OAI-SearchBot", Vendor: vendorOpenAI, Class: Search},
	{Name: "ChatGPT-User", Vendor: vendorOpenAI, Class: User},
	{Name: "ClaudeBot", Vendor: vendorAnthropic, Class: Training},
	{Name: "Claude-SearchBot", Vendor: vendorAnthropic, Class: Search},
	{Name: "Claude-User", Vendor: vendorAnthropic, Class: User},
	{Name: "PerplexityBot", Vendor: vendorPerplexity, Class: Search},
	{Name: "Perplexity-User", Vendor: vendorPerplexity, Class: User},
	{Name: "CCBot", Vendor: "Common Crawl", Class: Training},
	{Name: "Bytespider", Vendor: "ByteDance", Class: Training},
	{Name: "Amazonbot", Vendor: "Amazon", Class: Training},
	{Name: "meta-externalagent", Vendor: "Meta", Class: Training},
}

// Catalog returns every agent the gateway recognises.
func Catalog() []Agent { return append([]Agent(nil), catalog[:]...) }

// Known reports whether name is an agent in the catalog.
func Known(name string) bool {
	for i := range catalog {
		if catalog[i].Name == name {
			return true
		}
	}
	return false
}

// Claim returns the agent a User-Agent names, if it names one. It allocates
// nothing, so a route can ask on every request.
func Claim(ua string) (Agent, bool) {
	if ua == "" {
		return Agent{}, false
	}
	for i := range catalog {
		if strings.Contains(ua, catalog[i].Name) {
			return catalog[i], true
		}
	}
	return Agent{}, false
}
