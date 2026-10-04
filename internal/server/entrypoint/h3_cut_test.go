// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go/http3"
)

// DP-N4. An HTTP/3 response cut by the entrypoint's write deadline ended with a
// clean end of stream. A streamed response carries no Content-Length, so the
// client had nothing to compare against: a 64 MiB download stopped at 77 KB and
// read as complete. Over HTTP/1 and HTTP/2 the same cut closes the connection
// or resets the stream. Two things made HTTP/3 different: quic-go closes the
// stream cleanly when the handler returns, whatever its writes did, and
// httputil.ReverseProxy only aborts (panics with http.ErrAbortHandler) when the
// request context carries http.ServerContextKey, which quic-go does not set,
// so the proxy returned normally after its copy failed.

// bigBackendAddr serves 64 MiB to every request.
func bigBackendAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: writingHandler(make(chan error, 64)), ReadHeaderTimeout: streamTestBound}
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(ln) })
	t.Cleanup(func() { _ = srv.Close(); wg.Wait() })
	return ln.Addr().String()
}

// startH3DeadlineEP starts an HTTP/3 entrypoint with epDeadline timeouts in
// front of h and returns its address and a client for it.
func startH3DeadlineEP(t *testing.T, h http.Handler) (string, *http.Client) {
	t.Helper()
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	deps.BaseHandler = h
	ms := int32(epDeadline / time.Millisecond)
	ep := &gateonv1.EntryPoint{Id: "h3-cut", Address: freeTCPAndUDPAddr(t), Type: gateonv1.EntryPoint_HTTP3,
		Tls: &gateonv1.TlsConfig{Enabled: true}, ReadTimeoutMs: ms, WriteTimeoutMs: ms}
	addr := httpEntrypointFor(t, ep, deps)
	tr := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() { _ = tr.Close() })
	return addr, &http.Client{Transport: tr}
}

// signalEnd reports on ended when h returns, normally or by panicking.
func signalEnd(h http.Handler, ended chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { ended <- struct{}{} }()
		h.ServeHTTP(w, r)
	})
}

// TestHTTP3RequestsCarryTheServerContextKey pins the half of DP-N4 that lets
// httputil.ReverseProxy abort a cut copy itself, rather than return normally
// and log "suppressing panic" to stderr once per cut response.
func TestHTTP3RequestsCarryTheServerContextKey(t *testing.T) {
	seen := make(chan bool, 1)
	addr, client := startH3DeadlineEP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Context().Value(http.ServerContextKey) != nil
		w.WriteHeader(http.StatusNoContent)
	}))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if !<-seen {
		t.Error("an HTTP/3 request has no http.ServerContextKey; ReverseProxy will not abort a cut copy")
	}
}

func TestAnHTTP3ResponseCutByTheDeadlineIsReset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(t *testing.T) http.Handler
	}{
		{"handler", func(*testing.T) http.Handler { return writingHandler(make(chan error, 1)) }},
		{"proxied", func(t *testing.T) http.Handler { return proxyTo(t, bigBackendAddr(t)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ended := make(chan struct{}, 1)
			addr, client := startH3DeadlineEP(t, signalEnd(tc.handler(t), ended))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/big", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			// Read nothing until the handler is done: flow control stalls its
			// writes and the write deadline cuts them.
			select {
			case <-ended:
			case <-time.After(streamTestBound):
				t.Fatalf("the handler was still writing %v later; the deadline did not apply", streamTestBound)
			}
			n, err := io.Copy(io.Discard, resp.Body)
			if err == nil {
				t.Fatalf("a response cut after %d of 67108864 bytes ended cleanly (Content-Length %d): "+
					"the client cannot tell it is incomplete", n, resp.ContentLength)
			}
		})
	}
}
