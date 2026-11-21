// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package connguard

import (
	"bytes"
	"io"
	"net/netip"
	"time"
)

// net/http's HTTP/2 server closes a connection with ENHANCE_YOUR_CALM when its
// client queues more streams than the server will run -- what a rapid-reset
// client does -- and reports it only through the server's error log, as
//
//	http2: server connection error from 10.0.0.1:5000: connection error: ENHANCE_YOUR_CALM
//
// In the 2026-11-17 lab that close came first for nine connections in ten,
// before the per-connection reset count saw enough cancelled handlers, so a
// cool-off started only by the count missed most of the attack. The log line
// is the one signal net/http gives; the address in it is the TCP peer, not
// anything the client wrote. TestTheServersCalmCloseStartsACoolOff pins the
// format against the real server, so a change to it fails the build rather
// than silently turning the cool-off off.
var (
	calmPrefix = []byte("http2: server connection error from ")
	calmSuffix = []byte(": connection error: ENHANCE_YOUR_CALM")
)

// WatchServerErrors returns a writer for an http.Server's ErrorLog that
// starts a cool-off for each peer the server closes with ENHANCE_YOUR_CALM,
// under the key keyOf gives its IP -- keyOf reports false for an address that
// is never capped -- and passes every line on to next. It returns next itself
// when c is nil.
func (c *CoolOff) WatchServerErrors(next io.Writer, keyOf func(ip string) (netip.Addr, bool)) io.Writer {
	if c == nil {
		return next
	}
	return &calmWatcher{next: next, c: c, keyOf: keyOf}
}

type calmWatcher struct {
	next  io.Writer
	c     *CoolOff
	keyOf func(ip string) (netip.Addr, bool)
}

func (w *calmWatcher) Write(p []byte) (int, error) {
	if ip, ok := calmPeer(p); ok {
		if key, ok := w.keyOf(ip); ok {
			w.c.Start(key, time.Now())
		}
	}
	return w.next.Write(p)
}

// calmPeer is the peer IP in an ENHANCE_YOUR_CALM close line.
func calmPeer(line []byte) (string, bool) {
	i := bytes.Index(line, calmPrefix)
	if i < 0 {
		return "", false
	}
	rest := line[i+len(calmPrefix):]
	j := bytes.Index(rest, calmSuffix)
	if j < 0 {
		return "", false
	}
	ap, err := netip.ParseAddrPort(string(rest[:j]))
	if err != nil {
		return "", false
	}
	return ap.Addr().Unmap().String(), true
}
