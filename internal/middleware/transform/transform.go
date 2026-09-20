// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// MaxBodyBytes bounds what BodyTransform holds in memory per side.
const MaxBodyBytes = 10 << 20

// BodyTransformConfig configures the body transformation middleware.
type BodyTransformConfig struct {
	RequestSearch     string
	RequestReplace    string
	ResponseSearch    string
	ResponseReplace   string
	ContentTypeFilter string // e.g. "application/json"
}

// BodyTransform returns a middleware that replaces strings in request and response bodies.
func BodyTransform(cfg BodyTransformConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Content-Type check
			if cfg.ContentTypeFilter != "" {
				ct := r.Header.Get("Content-Type")
				if !strings.Contains(ct, cfg.ContentTypeFilter) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Request transformation
			if cfg.RequestSearch != "" && r.Body != nil {
				transformRequestBody(r, cfg)
			}

			if cfg.ResponseSearch == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Response transformation
			bw := &transformResponseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(bw, r)
			bw.finish(cfg.ResponseSearch, cfg.ResponseReplace)
		})
	}
}

// transformRequestBody rewrites the request body in place, up to the buffer
// bound. A body over the bound is forwarded as it arrived: the alternative is
// holding an attacker-chosen number of bytes per in-flight request.
func transformRequestBody(r *http.Request, cfg BodyTransformConfig) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return
	}
	if len(body) > MaxBodyBytes {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		return
	}
	_ = r.Body.Close()
	newBody := strings.ReplaceAll(string(body), cfg.RequestSearch, cfg.RequestReplace)
	r.Body = io.NopCloser(bytes.NewBufferString(newBody))
	r.ContentLength = int64(len(newBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
}

type transformResponseWriter struct {
	http.ResponseWriter
	body        bytes.Buffer
	status      int
	wroteHeader bool
	// passthrough records that the held-back header has already gone out
	// unchanged, so nothing may be rewritten from here on.
	passthrough bool
}

// Write buffers the body so the rewritten length can be declared. The status
// line is held back with it: the old writer forwarded WriteHeader immediately,
// which put the origin's Content-Length on the wire before the body was
// rewritten, and the client then read a truncated response.
func (bw *transformResponseWriter) Write(b []byte) (int, error) {
	if !bw.wroteHeader {
		bw.WriteHeader(http.StatusOK)
	}
	if bw.passthrough {
		return bw.ResponseWriter.Write(b)
	}
	if bw.body.Len()+len(b) > MaxBodyBytes {
		bw.startPassthrough()
		return bw.ResponseWriter.Write(b)
	}
	return bw.body.Write(b)
}

func (bw *transformResponseWriter) WriteHeader(code int) {
	if bw.wroteHeader {
		return
	}
	bw.wroteHeader = true
	bw.status = code
}

// startPassthrough gives up on transforming this response and releases what is
// held, with the origin's own headers, which still describe those bytes.
func (bw *transformResponseWriter) startPassthrough() {
	bw.passthrough = true
	bw.ResponseWriter.WriteHeader(bw.status)
	if bw.body.Len() > 0 {
		// #nosec G705 -- origin bytes forwarded verbatim, nothing interpolated.
		_, _ = bw.ResponseWriter.Write(bw.body.Bytes())
		bw.body.Reset()
	}
}

// finish emits the held-back response, with a Content-Length that matches the
// bytes actually sent.
func (bw *transformResponseWriter) finish(search, replace string) {
	if bw.passthrough {
		return
	}
	if !bw.wroteHeader {
		bw.WriteHeader(http.StatusOK)
	}
	out := bw.body.Bytes()
	if bw.status < 400 {
		out = []byte(strings.ReplaceAll(bw.body.String(), search, replace))
		// The body no longer matches the origin's validator.
		bw.ResponseWriter.Header().Del("ETag")
	}
	bw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(out)))
	bw.ResponseWriter.WriteHeader(bw.status)
	if len(out) > 0 {
		// #nosec G705 -- origin bytes with the operator's configured replacement.
		_, _ = bw.ResponseWriter.Write(out)
	}
}

// Hijack forwards to the underlying writer so a WebSocket upgrade behind this
// middleware can take the raw connection. Without it, wrapping the writer to
// buffer the body silently strips the http.Hijacker the proxy asserts on, and
// every upgrade on a route with body transformation fails with 500. Body
// transformation does not apply to a hijacked connection anyway — there is no
// HTTP response body to rewrite once the socket is switched to WebSocket.
func (bw *transformResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := bw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

// Flush means the handler wants bytes on the wire now, which is incompatible
// with holding them back to rewrite them. Release what is held and stream the
// rest untransformed rather than buffering a stream that may never end.
func (bw *transformResponseWriter) Flush() {
	if !bw.passthrough {
		if !bw.wroteHeader {
			bw.WriteHeader(http.StatusOK)
		}
		bw.startPassthrough()
	}
	if f, ok := bw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
