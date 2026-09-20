// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// A WebSocket upgrade works by taking the raw connection away from net/http
// via http.Hijacker. Any middleware that substitutes the ResponseWriter has to
// carry that capability forward, because the assertion is made on whatever
// object reaches the handler — not on the original writer.
//
// wafResponseWriter wraps the response so the engine can inspect it, which puts
// it directly in the path of every upgrade on a WAF-enabled route. Regression
// for the e2e failure "Expected 101 Switching Protocols, got 500" /
// "hijack failed" on the Synology WebSocket route.

// hijackableRecorder is an httptest.ResponseRecorder that also implements
// http.Hijacker, standing in for the real connection-backed writer.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	client, server := net.Pipe()
	go func() { _, _ = server.Write(nil); _ = server.Close() }()
	return client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), nil
}

func TestWAF_PreservesHijackerForWebSocketUpgrade(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	var (
		sawHijacker bool
		hijackErr   error
	)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		sawHijacker = ok
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		hijackErr = err
		if conn != nil {
			_ = conn.Close()
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req = req.WithContext(context.WithValue(req.Context(),
		request.RequestStateContextKey{}, &request.RequestState{}))

	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(rec, req)

	if !sawHijacker {
		t.Fatal("handler behind the WAF did not receive an http.Hijacker.\n" +
			"wafResponseWriter replaces the ResponseWriter without forwarding Hijack, " +
			"so every WebSocket upgrade on a WAF-enabled route fails with 500.")
	}
	if hijackErr != nil {
		t.Fatalf("Hijack through the WAF response writer failed: %v", hijackErr)
	}
	if !rec.hijacked {
		t.Error("Hijack did not reach the underlying connection-backed writer")
	}
}

// countingHijacker records what the WAF's response writer does to the
// underlying connection after the handler has hijacked it.
type countingHijacker struct {
	*httptest.ResponseRecorder
	writeHeaderAfterHijack int
	hijacked               bool
}

func (h *countingHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	client, server := net.Pipe()
	go func() { _ = server.Close() }()
	return client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), nil
}

func (h *countingHijacker) WriteHeader(status int) {
	if h.hijacked {
		h.writeHeaderAfterHijack++
		return
	}
	h.ResponseRecorder.WriteHeader(status)
}

// TestWAF_NoWriteHeaderAfterHijack: once the connection is hijacked net/http
// owns nothing about it any more, and a WriteHeader on it is logged by the
// server as a programming error — one line per WebSocket upgrade on every
// route with response inspection on. finish() has to know the response left
// through Hijack and stand down.
func TestWAF_NoWriteHeaderAfterHijack(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, EnableResponseInspection: true})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no Hijacker behind the WAF")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close()
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := &countingHijacker{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(rec, req)

	if !rec.hijacked {
		t.Fatal("Hijack did not reach the underlying writer")
	}
	if rec.writeHeaderAfterHijack != 0 {
		t.Fatalf("WriteHeader called %d time(s) on a hijacked connection", rec.writeHeaderAfterHijack)
	}
}

// TestResponseWriterWrappersPreserveHijacker covers every body-rewriting
// middleware, not just the WAF. Each wraps http.ResponseWriter to inspect or
// modify the response body, and any that forgets to forward Hijack silently
// breaks WebSocket upgrades on every route it sits on. This was the cause of
// the "hijack failed" 500 on the Synology WebSocket e2e route, where a body
// transformation middleware stripped the Hijacker.
func TestResponseWriterWrappersPreserveHijacker(t *testing.T) {
	wrappers := map[string]http.ResponseWriter{
		// transformResponseWriter moved to internal/middleware/transform with
		// BodyTransform; its half of this guard lives there, in
		// TestTransformResponseWriterPreservesHijacker.
		"deceptionResponseWriter": &deceptionResponseWriter{},
		"breadcrumbWriter":        &breadcrumbWriter{},
		"wafResponseWriter":       &wafResponseWriter{},
	}

	for name, w := range wrappers {
		t.Run(name, func(t *testing.T) {
			if _, ok := w.(http.Hijacker); !ok {
				t.Errorf("%s does not implement http.Hijacker; every WebSocket "+
					"upgrade on a route using it fails with 500", name)
			}
		})
	}
}
