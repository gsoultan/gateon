// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
)

// ErrorsConfig defines the configuration for the errors middleware.
type ErrorsConfig struct {
	// StatusCodes is the list of status codes that should trigger the custom error page.
	StatusCodes []int
	// CustomPages is a map of status code to custom HTML body.
	CustomPages map[int]string
}

// errorResponseWriter wraps http.ResponseWriter to intercept error status codes
// and replace the response body with a custom error page.
type errorResponseWriter struct {
	http.ResponseWriter
	status      int
	matchedPage string
	wroteHeader bool
	codes       []int
	pages       map[int]string
}

func (w *errorResponseWriter) WriteHeader(code int) {
	if w.wroteHeader || w.matchedPage != "" {
		return
	}
	w.status = code
	if page, ok := w.pages[code]; ok {
		w.matchedPage = page
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *errorResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.matchedPage != "" {
		// Drop the downstream error body as we'll replace it.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Flush forwards a flush unless the body is being replaced. The writer used to
// embed only the ResponseWriter interface, which promotes Header, Write and
// WriteHeader and nothing else, so behind this middleware nothing could flush:
// server-sent events arrived all at once when the handler returned.
func (w *errorResponseWriter) Flush() {
	if w.matchedPage != "" {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying connection. Without it the proxy answered
// every websocket upgrade on a route with this middleware 500.
func (w *errorResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *errorResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// representationHeaders describe the body the page replaces. Left in place,
// the backend's Content-Length cut the page off at the length of the backend's
// own error body, and its Content-Encoding announced plain HTML as gzip.
var representationHeaders = []string{
	"Content-Length", "Content-Encoding", "Content-Range", "Transfer-Encoding", "Etag", "Last-Modified",
}

func servePage(w http.ResponseWriter, status int, page string) {
	h := w.Header()
	for _, k := range representationHeaders {
		h.Del(k)
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(page)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

// Errors returns a middleware that handles custom error pages by intercepting
// error status codes and replacing the response body.
func Errors(cfg ErrorsConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ew := &errorResponseWriter{
				ResponseWriter: w,
				codes:          cfg.StatusCodes,
				pages:          cfg.CustomPages,
			}
			next.ServeHTTP(ew, r)

			if ew.matchedPage != "" {
				servePage(w, ew.status, ew.matchedPage)
			}
		})
	}
}
