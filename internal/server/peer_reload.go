// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// A peer's invalidation used to clear this node's proxy caches and nothing
// else. The caches were rebuilt from the registries, and the registries are
// read from the database once, at start-up -- so a route, service, middleware,
// entrypoint, TLS option or WAF rule another gateway wrote was never seen
// here until a restart, and the message that announced it cost a rebuild
// of the same stale configuration (ADR 0080). Every message now re-reads the
// registries the message can concern before the caches are cleared.

// configReloader re-reads one registry from the database, replacing what it
// holds. The database-backed registries and the WAF rule store implement it;
// a file-backed registry does not, and is left as it is.
type configReloader interface {
	Reload(ctx context.Context) error
}

// peerReloadTimeout bounds one reload. A database that does not answer must
// not hold the listener, and with it every later invalidation.
const peerReloadTimeout = 30 * time.Second

// peerReloaders is what a peer's message re-reads, by name for the log.
type peerReloaders struct {
	config []namedReloader // routes, services, middlewares, entrypoints, TLS options
	waf    []namedReloader
}

type namedReloader struct {
	name string
	r    configReloader
}

// reloadersOf collects the registries of s that can re-read themselves.
func reloadersOf(s *Server) *peerReloaders {
	p := &peerReloaders{}
	add := func(dst *[]namedReloader, name string, v any) {
		if r, ok := v.(configReloader); ok && r != nil {
			*dst = append(*dst, namedReloader{name: name, r: r})
		}
	}
	add(&p.config, "routes", s.RouteStore)
	add(&p.config, "services", s.ServiceStore)
	add(&p.config, "middlewares", s.MwStore)
	add(&p.config, "entrypoints", s.EpStore)
	add(&p.config, "tls options", s.TLSOptStore)
	add(&p.waf, "waf rules", s.WafRules)
	return p
}

// forMessage re-reads the registries a message of type t concerns: the
// configuration for a route, TLS or global message, the WAF rules for a WAF
// message. A registry whose read fails is logged and left as it was; the
// invalidation still runs, since a stale rebuild is no worse than before.
func (p *peerReloaders) forMessage(t string) {
	if p == nil {
		return
	}
	var set []namedReloader
	switch t {
	case "route", "all", "tls":
		set = p.config
	case "waf":
		set = p.waf
	default:
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerReloadTimeout)
	defer cancel()
	for _, nr := range set {
		if err := nr.r.Reload(ctx); err != nil {
			logger.L.LogError("peer invalidation: registry not reloaded; this node keeps serving what it had",
				"registry", nr.name, "error", err)
		}
	}
}
