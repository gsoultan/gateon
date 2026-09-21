// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/art"
)

// The IP filter implementation, lifted out of standard.go so it sits with the
// factory that builds it. It is the third instance of this stage's recurring
// shape -- a group's code living in a file the group does not own -- after
// parseListStrict and spanLogger in the earlier stages.

// ipFilterData holds pre-parsed IP filter rules optimized for lookups.
type ipFilterData struct {
	exactAllow map[string]struct{}
	treeAllow  *art.Tree
	exactDeny  map[string]struct{}
	treeDeny   *art.Tree

	// allowConfigured records that an allow list was *asked for*, separately
	// from whether any of it parsed. An empty allow structure means "no allow
	// list" -- allow everyone -- so without this an allow list whose entries
	// all failed to parse silently became no allow list at all. A single typo
	// ("10.0.0/8" for "10.0.0.0/8") turned a restricted route into an open
	// one, with nothing logged. Verified: such a filter answered 200 to
	// 203.0.113.9.
	allowConfigured bool
}

func newIPFilterData(allowList, denyList []string) *ipFilterData {
	d := &ipFilterData{
		exactAllow: make(map[string]struct{}),
		treeAllow:  art.NewTree(),
		exactDeny:  make(map[string]struct{}),
		treeDeny:   art.NewTree(),
	}
	for _, r := range allowList {
		if strings.TrimSpace(r) != "" {
			// Recorded before the parse, because the parse is what fails.
			d.allowConfigured = true
		}
		if strings.Contains(r, "/") {
			if err := d.treeAllow.InsertCIDR(r); err != nil {
				logger.L.LogWarn("ip filter: allow_list entry is not a valid CIDR and was dropped; "+
					"the entry restricts nothing", "entry", r, "error", err)
			}
		} else {
			d.exactAllow[r] = struct{}{}
			// Also insert into tree for consistency
			_ = d.treeAllow.InsertCIDR(r + "/32")
		}
	}
	for _, r := range denyList {
		if strings.Contains(r, "/") {
			if err := d.treeDeny.InsertCIDR(r); err != nil {
				logger.L.LogWarn("ip filter: deny_list entry is not a valid CIDR and was dropped; "+
					"the address it names is NOT blocked", "entry", r, "error", err)
			}
		} else {
			d.exactDeny[r] = struct{}{}
			_ = d.treeDeny.InsertCIDR(r + "/32")
		}
	}
	return d
}

func (d *ipFilterData) matches(clientIP string) bool {
	// Deny list takes precedence
	if _, ok := d.exactDeny[clientIP]; ok {
		return true
	}
	return d.treeDeny.Contains(clientIP)
}

func (d *ipFilterData) allowed(clientIP string) bool {
	if len(d.exactAllow) == 0 && d.treeAllow.IsEmpty() {
		// Configured but unusable is not the same as unconfigured. An operator
		// who wrote an allow list meant to restrict something, so a list that
		// parsed to nothing denies rather than admitting everyone -- the
		// entries are logged as they are dropped, so the cause is visible.
		return !d.allowConfigured
	}
	if _, ok := d.exactAllow[clientIP]; ok {
		return true
	}
	return d.treeAllow.Contains(clientIP)
}

// IPFilterWithClientIP returns a middleware that filters requests by IP address using the given clientIP resolver.
func IPFilterWithClientIP(allowList, denyList []string, clientIP func(*http.Request) string) kind.Middleware {
	data := newIPFilterData(allowList, denyList)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS-preflight exemption, deliberately. IsCorsPreflight is
			// three values the client writes -- the OPTIONS method, an Origin
			// header and an Access-Control-Request-Method header -- so
			// skipping on it made this boundary opt-out. transform.GlobalCORS
			// terminates preflights ahead of the HTTP entrypoint's chain, but
			// it has one call site and neither the management listener nor the
			// smart-TCP listener includes it: measured there, a request from
			// an address outside the allowlist reached the backend by naming a
			// preflight while the same request as a GET got 403.
			//
			// This states who may reach the gateway at all, so it answers
			// before considering what the caller says it wants. A browser
			// preflighting from a permitted address is unaffected.
			remoteAddr := clientIP(r)

			if data.matches(remoteAddr) {
				httputil.WriteForbidden(w, r, "Forbidden")
				return
			}

			if !data.allowed(remoteAddr) {
				httputil.WriteForbidden(w, r, "Forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPFilter returns a middleware that filters requests by IP address, using X-Forwarded-For and RemoteAddr.
// For Cloudflare, use IPFilterWithClientIP with a resolver that uses CF-Connecting-IP.
func IPFilter(allowList, denyList []string) kind.Middleware {
	return IPFilterWithClientIP(allowList, denyList, func(r *http.Request) string {
		return request.GetClientIP(r, config.EffectiveTrustCloudflare())
	})
}
