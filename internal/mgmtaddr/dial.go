// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mgmtaddr

import (
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gsoultan/gateon/internal/cloudmeta"
	"github.com/gsoultan/gateon/internal/logger"
)

// ErrManagementListener is the error a refused connection fails with: the
// address it was about to connect to is this gateway's management listener.
var ErrManagementListener = errors.New("refused: the address is this gateway's management listener")

// ErrCloudMetadata is the error a refused connection fails with when the
// address it was about to connect to is a cloud instance metadata service
// (ADR 0077).
var ErrCloudMetadata = errors.New("refused: the address is a cloud instance metadata service")

// Control is a net.Dialer Control hook that refuses a backend connection to
// the management listener (ADR 0052) or to a cloud instance metadata service
// (ADR 0077). It runs after the name is resolved, on the address actually
// being connected to, so a target saved as a name that later resolves to this
// host or to 169.254.169.254 is refused as surely as one saved as the
// address. Every dialer that carries data-plane traffic to a backend installs
// it.
//
// A connection costs a parse, a handful of comparisons against the metadata
// addresses and one against the management port, and allocates nothing.
func Control(network, address string, _ syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil // both listeners refused here answer TCP only
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil
	}
	if cloudmeta.IsMetadataAddr(ap.Addr()) {
		warnRefused(&lastMetadataWarn, address, "refused a backend connection to a cloud instance "+
			"metadata service; a service target resolves to it (ADR 0077)")
		return ErrCloudMetadata
	}
	if !Reaches(ap) {
		return nil
	}
	warnRefused(&lastRefusalWarn, address, "refused a backend connection to this gateway's own "+
		"management listener; a service target resolves to it (ADR 0052)")
	return ErrManagementListener
}

// refusalWarnEvery spaces the warnings refused connections log: a route that
// sends every request to a refused target must not become a log line per
// request.
const refusalWarnEvery = time.Minute

var lastRefusalWarn, lastMetadataWarn atomic.Int64

// warnRefused logs msg about address at most once a refusalWarnEvery per
// last.
func warnRefused(last *atomic.Int64, address, msg string) {
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(refusalWarnEvery) || !last.CompareAndSwap(prev, now) {
		return
	}
	logger.L.LogWarn(msg, "address", address)
}
