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
