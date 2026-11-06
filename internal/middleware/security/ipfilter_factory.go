// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
)

// NewIPFilter builds the ip filter from its stored settings, refusing an entry
// it cannot read (ADR 0047). Such an entry used to be dropped with a WARN while
// the save answered 200: a deny list of "127.0.0.*" blocked nothing. Every
// transport validates a middleware by building it, so this one refusal covers
// the dashboard, gRPC and config import, and a route whose stored filter no
// longer builds is refused (503) rather than served unfiltered.
func NewIPFilter(cfg map[string]string) (kind.Middleware, error) {
	allowList := kind.ParseListStrict(cfg["allow_list"])
	denyList := kind.ParseListStrict(cfg["deny_list"])
	if err := ValidateIPList("allow_list", allowList); err != nil {
		return nil, err
	}
	if err := ValidateIPList("deny_list", denyList); err != nil {
		return nil, err
	}
	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	clientIP := func(r *http.Request) string { return request.GetClientIP(r, trust) }
	return IPFilterWithClientIP(allowList, denyList, clientIP), nil
}

// NewAddrFilter builds the same allow and deny lists as NewIPFilter, as a
// decision about a connection's peer address rather than about an HTTP
// request. It is what an ipfilter middleware means on a TCP route (SSH, RDP,
// raw TCP), where there are no headers to read: the address is the TCP peer
// and nothing the client sends can change it, so trust_cloudflare_headers has
// nothing to apply to and is ignored. The lists are validated exactly as
// NewIPFilter validates them, so an entry it refuses is refused here too.
func NewAddrFilter(cfg map[string]string) (func(netip.Addr) bool, error) {
	allowList := kind.ParseListStrict(cfg["allow_list"])
	denyList := kind.ParseListStrict(cfg["deny_list"])
	if err := ValidateIPList("allow_list", allowList); err != nil {
		return nil, err
	}
	if err := ValidateIPList("deny_list", denyList); err != nil {
		return nil, err
	}
	data := newIPFilterData(allowList, denyList)
	return func(addr netip.Addr) bool {
		// Unmapped so ::ffff:203.0.113.9 is judged as the IPv4 address it is,
		// the form the lists are written in.
		ip := addr.Unmap().String()
		return !data.matches(ip) && data.allowed(ip)
	}, nil
}

// ValidateIPList refuses the first entry of a list that is neither an IP
// address nor a CIDR, naming key and the entry. Wildcards ("10.0.0.*") and
// ranges ("10.0.0.1-10.0.0.9") are not supported; write the CIDR.
func ValidateIPList(key string, entries []string) error {
	for _, e := range entries {
		if err := checkFilterEntry(e); err != nil {
			return kind.CfgError(key, e, err)
		}
	}
	return nil
}

// checkFilterEntry accepts exactly what addFilterEntry can record.
func checkFilterEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err
	}
	_, err := netip.ParseAddr(entry)
	return err
}
