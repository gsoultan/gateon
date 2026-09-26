// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/netip"
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
	// Recorded before any parse, because the parse is what fails. An allow list
	// of nothing but blanks is still an allow list somebody wrote.
	d.allowConfigured = len(allowList) > 0
	for _, r := range allowList {
		if err := addFilterEntry(d.treeAllow, d.exactAllow, r); err != nil {
			logger.L.LogWarn("ip filter: allow_list entry is not a valid IP or CIDR and was dropped; "+
				"the entry restricts nothing", "entry", r, "error", err)
		}
	}
	for _, r := range denyList {
		if err := addFilterEntry(d.treeDeny, d.exactDeny, r); err != nil {
			logger.L.LogWarn("ip filter: deny_list entry is not a valid IP or CIDR and was dropped; "+
				"the address it names is NOT blocked", "entry", r, "error", err)
		}
	}
	return d
}

// addFilterEntry records one list entry: a CIDR as written, or a bare address
// as exactly one host -- /32 for IPv4, /128 for IPv6.
//
// Bare entries used to be inserted as entry+"/32" whatever their family. For
// IPv6 that is 2^96 addresses, so allow_list "2001:db8::1" admitted all of
// 2001:db8::/32 and deny_list "2001:db8::1" refused all of it. The management
// listener builds its allowlist here too, from "127.0.0.1,::1" by default, so
// an operator who allowlisted one IPv6 administrator opened the management
// plane to that address's whole /32.
//
// Entries are trimmed: GATEON_MANAGEMENT_ALLOWED_IPS is split on commas with no
// trimming, so "127.0.0.1, 10.0.0.5" produced " 10.0.0.5", which never matched
// and was never reported.
func addFilterEntry(tree *art.Tree, exact map[string]struct{}, entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	if strings.Contains(entry, "/") {
		return tree.InsertCIDR(entry)
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return err
	}
	exact[entry] = struct{}{}
	return tree.InsertCIDR(netip.PrefixFrom(addr, addr.BitLen()).String())
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
			// skipping on it made this boundary opt-out. Measured on the
			// management and smart-TCP listeners, a request from an address
			// outside the allowlist reached the backend by naming a preflight
			// while the same request as a GET got 403. Since ADR-0015 no
			// listener answers preflights ahead of its chain, so every one of
			// them reaches this check.
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
