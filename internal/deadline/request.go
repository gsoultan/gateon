// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"io"
	"net/http"
	"time"
)

// RequestTimeouts are per-request bounds for a listener whose requests vary
// too much for one fixed read timeout: the management listener, where a
// 2FA code and a 128 MiB GeoIP database arrive on the same port (ADR 0042).
//
// A body is bounded by its progress rather than by a total. It has Read to
// begin arriving, and every byte that arrives buys 1/MinBodyRate of a second
// more, so an upload over a slow link finishes while a body sent one byte at a
// time is cut once Read has passed. Once the request is in, the handler has
// Write to answer, measured from then -- not from when the request began.
type RequestTimeouts struct {
	Read        time.Duration
	Write       time.Duration
	MinBodyRate int64 // bytes per second
}

// Handler applies t to every request next serves, and hands next a
// StreamWriter so a server-sent-event response is lifted to limits instead.
func (t RequestTimeouts) Handler(next http.Handler, limits StreamLimits) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		rc := http.NewResponseController(w)
		if r.Body == nil || r.Body == http.NoBody {
			// Nothing to read. On HTTP/1 the read deadline still governs the
			// server's background read, which cancels the request when it
			// passes, so it lasts as long as the handler has to answer.
			_ = rc.SetReadDeadline(now.Add(t.Write))
			_ = rc.SetWriteDeadline(now.Add(t.Write))
		} else {
			b := &rateBody{ReadCloser: r.Body, rc: rc, t: t, start: now}
			b.extend(now)
			r.Body = b
		}
		sw := NewStreamWriter(w, limits)
		defer Release(sw)
		next.ServeHTTP(sw, r)
	})
}

// rateBody is a request body whose read deadline moves on as it arrives.
type rateBody struct {
	io.ReadCloser
	rc    *http.ResponseController
	t     RequestTimeouts
	start time.Time
	read  int64
	done  bool
}

func (b *rateBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	switch {
	case err == io.EOF && !b.done:
		// The request is in: the handler's time starts now.
		b.done = true
		now := time.Now()
		_ = b.rc.SetReadDeadline(now.Add(b.t.Write))
		_ = b.rc.SetWriteDeadline(now.Add(b.t.Write))
	case n > 0:
		b.extend(time.Now())
	}
	return n, err
}

// extend sets the read deadline the bytes so far have earned, and a write
// deadline that leaves the handler its whole Write past it.
func (b *rateBody) extend(now time.Time) {
	earned := b.t.Read
	if b.t.MinBodyRate > 0 {
		earned += time.Duration(b.read * int64(time.Second) / b.t.MinBodyRate)
	}
	end := b.start.Add(earned)
	if end.Before(now) {
		end = now // already behind: the next read that blocks fails at once
	}
	_ = b.rc.SetReadDeadline(end)
	_ = b.rc.SetWriteDeadline(end.Add(b.t.Write))
}
