// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

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

// TestResponseWriterWrappersPreserveHijacker covers every body-rewriting
// middleware, not just the WAF. Each wraps http.ResponseWriter to inspect or
// modify the response body, and any that forgets to forward Hijack silently
// breaks WebSocket upgrades on every route it sits on. This was the cause of
// the "hijack failed" 500 on the Synology WebSocket e2e route, where a body
// transformation middleware stripped the Hijacker.
func TestResponseWriterWrappersPreserveHijacker(t *testing.T) {
	wrappers := map[string]http.ResponseWriter{
		"transformResponseWriter": &transformResponseWriter{},
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
