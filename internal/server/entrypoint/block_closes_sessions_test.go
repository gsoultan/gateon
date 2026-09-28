// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// A block used to reach only connections accepted after it: an HTTP entrypoint
// refuses a keep-alive connection at its next request, but an L4 session has no
// request boundary, so a shunned address's SSH, database or mail session ran on
// until it ended. eBPF, where it ran, dropped its packets; the plaintext L4
// path did not. A block now fires an event the TCP entrypoints answer by
// closing that address's open connections (ADR 0036).

// closedWithin reports whether c is closed within within: a read that ends with
// an error other than a timeout. A session still open blocks until the deadline
// and reports not-closed; one the entrypoint closed returns EOF at once.
func closedWithin(t *testing.T, c net.Conn, within time.Duration) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(within))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// TestABlockClosesAnAddressOpenL4Session: a session proxied through a TCP
// entrypoint is closed promptly when its address is blocked -- the block driven
// through the real mitigation write -- and a connection from a clean address
// through the same entrypoint is served meanwhile, so the accept loop is not
// held up by the close.
func TestABlockClosesAnAddressOpenL4Session(t *testing.T) {
	const blocked, clean = "198.51.100.101", "198.51.100.102"
	withTelemetryStore(t)
	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "block-open-tcp"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false) // tcp-only: proxied at accept
	// The blocked address first (its held session), then the clean address for
	// the connection opened after the block.
	tcpEntrypointFrom(t, ep, deps, nil, blocked, clean)

	session := echoSession(t, ep.Address, "hello\n") // established and proxied
	if n := sessions.Load(); n != 1 {
		t.Fatalf("the backend saw %d sessions before the block, want 1", n)
	}

	shun(t, blocked) // the real mitigation write fires the block event synchronously

	if !closedWithin(t, session, sessionBound) {
		t.Errorf("the open session from %s was not closed after its address was blocked", blocked)
	}
	// The accept loop kept accepting: a connection from a clean address, opened
	// after the block, is served.
	_ = echoed(t, dialBounded(t, ep.Address), "clean session\n")
}

// TestAnAutomaticShunClosesAnAddressOpenL4Session: an automatic shun -- a
// scanner or SSH brute-forcer earning its block -- reaches the shunned
// address's open session too, not only its next connection, through the same
// event the manual block fires.
func TestAnAutomaticShunClosesAnAddressOpenL4Session(t *testing.T) {
	const blocked = "198.51.100.131"
	withTelemetryStore(t)
	backend, _ := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "autoshun-open-tcp"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, nil, blocked)

	session := echoSession(t, ep.Address, "hello\n")

	res, err := telemetry.ShunAutomatically(blocked, "test: automatic shun")
	if err != nil {
		t.Fatalf("automatic shun of %s: %v", blocked, err)
	}
	if res.Outcome != telemetry.ShunApplied {
		t.Fatalf("the automatic shun of %s did not apply (outcome %v); the rest proves nothing", blocked, res.Outcome)
	}

	if !closedWithin(t, session, sessionBound) {
		t.Errorf("the open session from %s was not closed after it was shunned automatically", blocked)
	}
}

// TestABlockDoesNotCutAnAllowlistedAddressOpenSession: the block event honours
// the same exemption the accept-time check does (identity.AddressBlocked), so
// an operator who blocks an address they have also allowlisted does not cut its
// open session -- the allowlist is "never mitigated".
func TestABlockDoesNotCutAnAllowlistedAddressOpenSession(t *testing.T) {
	const allowlisted = "198.51.100.111"
	withTelemetryStore(t)
	mitigation.SetAllowlist(mitigation.ParseAllowlist(allowlisted + "/32"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	backend, _ := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "block-allowlisted-tcp"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, nil, allowlisted)

	session := echoSession(t, ep.Address, "hi\n")
	shun(t, allowlisted) // on the list, but exempt from enforcement

	if closedWithin(t, session, 500*time.Millisecond) {
		t.Errorf("the open session from allowlisted %s was cut when its address was blocked", allowlisted)
	}
	// closedWithin shortened the read deadline; restore it before proving the
	// session still echoes.
	_ = session.SetDeadline(time.Now().Add(sessionBound))
	_ = echoed(t, session, "still served\n")
}

// TestAReleasedAddressNewConnectionIsServedAfterABlock: a block closes the
// address's open session, and once the operator releases the address a new
// connection from it is served again -- the accept-time check reads the list
// live, so the release takes effect at once.
func TestAReleasedAddressNewConnectionIsServedAfterABlock(t *testing.T) {
	const addr = "198.51.100.121"
	withTelemetryStore(t)
	backend, _ := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "block-release-tcp"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, nil, addr) // every connection appears from addr

	session := echoSession(t, ep.Address, "before\n")
	shun(t, addr)
	if !closedWithin(t, session, sessionBound) {
		t.Fatalf("the open session from %s was not closed on the block", addr)
	}
	// While blocked, a new connection from the same address is refused at accept.
	if !refused(dialBounded(t, ep.Address), "while blocked\n") {
		t.Errorf("a new connection from blocked %s was served", addr)
	}
	if err := telemetry.MarkIPUnmitigated(addr); err != nil {
		t.Fatalf("release %s: %v", addr, err)
	}
	_ = echoed(t, dialBounded(t, ep.Address), "after release\n")
}
