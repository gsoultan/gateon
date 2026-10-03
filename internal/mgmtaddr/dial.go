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

	"github.com/gsoultan/gateon/internal/logger"
)

// ErrManagementListener is the error a refused connection fails with: the
// address it was about to connect to is this gateway's management listener.
var ErrManagementListener = errors.New("refused: the address is this gateway's management listener")

// Control is a net.Dialer Control hook that refuses a connection to the
// management listener. It runs after the name is resolved, on the address
// actually being connected to, so a target saved as a name that later
// resolves to this host is refused as surely as one saved as 127.0.0.1. Every
// dialer that carries data-plane traffic to a backend installs it.
//
// A connection to any port but the management port costs a parse and one
// comparison, and allocates nothing.
func Control(network, address string, _ syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil // the management listener is TCP only
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !Reaches(ap) {
		return nil
	}
	warnRefused(address)
	return ErrManagementListener
}

// refusalWarnEvery spaces the warnings refused connections log: a route that
// sends every request to a refused target must not become a log line per
// request.
const refusalWarnEvery = time.Minute

var lastRefusalWarn atomic.Int64

// warnRefused says a connection was refused, at most once a minute.
func warnRefused(address string) {
	now := time.Now().UnixNano()
	last := lastRefusalWarn.Load()
	if now-last < int64(refusalWarnEvery) || !lastRefusalWarn.CompareAndSwap(last, now) {
		return
	}
	logger.L.LogWarn("refused a backend connection to this gateway's own management listener; "+
		"a service target resolves to it (ADR 0052)", "address", address)
}
