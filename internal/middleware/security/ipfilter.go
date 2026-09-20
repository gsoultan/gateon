// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
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
}

func newIPFilterData(allowList, denyList []string) *ipFilterData {
	d := &ipFilterData{
		exactAllow: make(map[string]struct{}),
		treeAllow:  art.NewTree(),
		exactDeny:  make(map[string]struct{}),
		treeDeny:   art.NewTree(),
	}
	for _, r := range allowList {
		if strings.Contains(r, "/") {
			_ = d.treeAllow.InsertCIDR(r)
		} else {
			d.exactAllow[r] = struct{}{}
			// Also insert into tree for consistency
			_ = d.treeAllow.InsertCIDR(r + "/32")
		}
	}
	for _, r := range denyList {
		if strings.Contains(r, "/") {
			_ = d.treeDeny.InsertCIDR(r)
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
		return true
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
			if kind.IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
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
