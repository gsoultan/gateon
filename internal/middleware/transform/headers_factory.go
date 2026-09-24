// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"bufio"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
)

func NewHeaders(cfg map[string]string) (kind.Middleware, error) {
	stsValue, err := hstsValue(cfg)
	if err != nil {
		return nil, err
	}
	forceSTSHeader := kind.ParseBoolStrict(cfg["force_sts_header"], false)
	reqOps := headerOpsFor(cfg, "request")
	respOps := headerOpsFor(cfg, "response")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqOps.applyTo(r.Header)

			// request.IsSecure rather than r.TLS, which is nil behind a
			// TLS-terminating proxy.
			hw := &headersWriter{ResponseWriter: w, ops: respOps}
			if stsValue != "" && (forceSTSHeader || request.IsSecure(r)) {
				hw.sts = stsValue
			}
			next.ServeHTTP(hw, r)
		})
	}, nil
}

// headersWriter applies the response rules at the moment the response is
// committed, which is the only moment they can work.
//
// They used to be applied to the header map before next ran, when it held
// nothing of the backend's; the reverse proxy then Adds every backend header
// to that map. A del_response_ rule deleted a header that was not there yet,
// so X-Powered-By and Server came back, and a set_response_ value was joined
// by the backend's own as a second value -- for Referrer-Policy the last one
// wins, and it was the backend's. Applying them in WriteHeader sees the
// finished map, and it is still before anything is on the wire.
type headersWriter struct {
	http.ResponseWriter
	ops       headerOps
	sts       string
	committed bool
}

func (w *headersWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	h := w.Header()
	w.ops.applyTo(h)
	if w.sts != "" {
		h.Set("Strict-Transport-Security", w.sts)
	}
}

func (w *headersWriter) WriteHeader(code int) {
	// An informational response is not the response; its headers go out on
	// their own and the final ones are still being assembled.
	if code >= http.StatusOK {
		w.commit()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *headersWriter) Write(b []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer, committing the headers first,
// since flushing is what puts them on the wire.
func (w *headersWriter) Flush() {
	w.commit()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer for the
// controls this wrapper does not forward itself, such as write deadlines.
func (w *headersWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack forwards to the underlying writer so upgrades keep working behind
// this middleware.
func (w *headersWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// headerOp is one configured mutation, with its prefix already stripped.
type headerOp struct {
	action string // "add", "set" or "del"
	name   string
	value  string
}

// headerOps is the set of mutations for one direction, resolved once when the
// route is built.
//
// This used to walk the whole config map twice per request -- once for the
// request direction, once for the response -- testing six prefixes against
// every key and calling TrimPrefix on each hit, to recompute an answer that
// cannot change between requests. A route with twenty settings paid a hundred
// and twenty string comparisons per request for it.
type headerOps []headerOp

// headerOpsFor extracts the "<action>_<direction>_<name>" settings for one
// direction. The result is sorted by config key so two rules touching the same
// header apply in a fixed order; ranging a map gave a different order per
// request, which meant a config with both set_request_x and del_request_x
// behaved differently on consecutive calls.
func headerOpsFor(cfg map[string]string, direction string) headerOps {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var ops headerOps
	for _, k := range keys {
		for _, action := range [...]string{"add", "set", "del"} {
			prefix := action + "_" + direction + "_"
			if name, ok := strings.CutPrefix(k, prefix); ok && name != "" {
				ops = append(ops, headerOp{action: action, name: name, value: cfg[k]})
				break
			}
		}
	}
	return ops
}

func (ops headerOps) applyTo(h http.Header) {
	for _, op := range ops {
		switch op.action {
		case "add":
			h.Add(op.name, op.value)
		case "set":
			h.Set(op.name, op.value)
		case "del":
			h.Del(op.name)
		}
	}
}

// hstsValue builds the Strict-Transport-Security value once, when the route is
// built; "" when sts_seconds is unset or not positive.
//
// A malformed value is an error rather than a "". Both used to produce no
// header at all, which meant an operator who set sts_seconds and mistyped it
// got no HSTS and no indication of it -- the dashboard showed what they wrote
// and the response carried nothing.
func hstsValue(cfg map[string]string) (string, error) {
	stsSeconds, err := kind.ParseIntStrict(cfg["sts_seconds"], 0)
	if err != nil {
		return "", kind.CfgError("sts_seconds", cfg["sts_seconds"], err)
	}
	if stsSeconds <= 0 {
		return "", nil
	}
	val := "max-age=" + strconv.Itoa(stsSeconds)
	if kind.ParseBoolStrict(cfg["sts_include_subdomains"], false) {
		val += "; includeSubDomains"
	}
	if kind.ParseBoolStrict(cfg["sts_preload"], false) {
		val += "; preload"
	}
	return val, nil
}
