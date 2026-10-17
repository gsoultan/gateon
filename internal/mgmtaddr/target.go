// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mgmtaddr

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/cloudmeta"
)

// resolveTimeout bounds the name lookup a save makes for a target on the
// management port's number. A lookup that does not finish in time is not a
// refusal: the connection is still checked when it is dialled.
const resolveTimeout = 2 * time.Second

// defaultPorts are the ports a target URL connects to when it names none.
// h3 and udp are absent on purpose: they are UDP, and the management listener
// is TCP only.
var defaultPorts = map[string]int{
	"http": 80, "ws": 80, "h2c": 80,
	"https": 443, "wss": 443, "h2": 443,
}

// CheckTarget returns an error naming raw when it is a service target the
// data plane refuses to connect to: a cloud instance metadata service (ADR
// 0077), written as its address or as one of the names it is published under,
// or this gateway's management listener (ADR 0052) -- the management port, on
// a loopback, unspecified or own address of this host, written as one or as a
// name that resolves to one. A name is not resolved for the metadata check,
// and the management check returns nil when no management listener has bound,
// when raw does not say where it connects, and when its name does not
// resolve: the connection is refused again at dial time (Control), which is
// the check that cannot be outrun by a name that changes.
func CheckTarget(ctx context.Context, raw string) error {
	if err := checkMetadataTarget(raw); err != nil {
		return err
	}
	p := Port()
	if p == 0 {
		return nil
	}
	host, tport, ok := targetHostPort(raw)
	if !ok || tport != p {
		return nil
	}
	for _, a := range resolve(ctx, host) {
		if isLocal(a) {
			return fmt.Errorf("target %s connects to this gateway's own management listener "+
				"(port %d on %s, an address of this host); the gateway does not proxy to its "+
				"dashboard and API -- to reach them through an entrypoint, an administrator enables "+
				"public management instead", raw, p, a)
		}
	}
	return nil
}

// checkMetadataTarget refuses raw when its host is a cloud instance metadata
// address or name, on any port and under any TCP scheme. A target with no
// scheme and no port ("169.254.169.254") is read as a bare host, which is how
// the proxy reads it.
func checkMetadataTarget(raw string) error {
	raw = strings.TrimSpace(raw)
	host, ok := targetHost(raw)
	if !ok || !cloudmeta.IsMetadataHostOrAddr(host) {
		return nil
	}
	return fmt.Errorf("target %s is a cloud instance metadata service; the gateway does not "+
		"proxy to it, because behind a route it hands this machine's identity and credentials "+
		"to whoever reaches that route (ADR 0077)", raw)
}

// targetHost is the host raw connects to, whatever its port. ok is false when
// raw is not a URL or connects over UDP (udp://, h3://).
func targetHost(raw string) (string, bool) {
	if !strings.Contains(raw, "://") {
		if h, _, err := net.SplitHostPort(raw); err == nil {
			return h, true
		}
		return raw, true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if s := strings.ToLower(u.Scheme); s == "udp" || s == "h3" {
		return "", false
	}
	return u.Hostname(), true
}

// targetHostPort is where raw connects: a URL's host and port (its scheme's
// default when it names none), or a bare host:port. ok is false when raw does
// not say, or connects over UDP (udp://, h3://), which the TCP-only management
// listener never answers.
func targetHostPort(raw string) (host string, port int, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		h, ps, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, false
		}
		n, err := strconv.Atoi(ps)
		return h, n, err == nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "udp" || scheme == "h3" {
		return "", 0, false
	}
	if scheme == "tcp" {
		scheme = "" // a bare host:port with a prefix: it must name its port
	}
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		return u.Hostname(), n, err == nil
	}
	n, known := defaultPorts[scheme]
	return u.Hostname(), n, known
}

// resolve is host's addresses: host itself when it is an address, the
// unspecified address when it is empty (a connect to which lands on this
// host), else what the system resolver answers within resolveTimeout.
func resolve(ctx context.Context, host string) []netip.Addr {
	if host == "" {
		return []netip.Addr{netip.IPv4Unspecified()}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	return addrs
}
