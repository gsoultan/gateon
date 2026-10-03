// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go/http3"
)

// These tests pin ADR 0042: an entrypoint's per-request deadlines are lifted
// only for a request that the server has answered as a stream, never because
// of a header the client wrote, and a stream is then bounded by an idle
// timeout and a maximum lifetime instead.

// streamTestBound is how long a test waits for something that, with the
// deadlines in force, happens in well under a second. Without them it never
// happens at all, which is what the tests detect.
const streamTestBound = 3 * time.Second

// epDeadline is the read and write timeout of the entrypoint the tests start.
const epDeadline = 300 * time.Millisecond

// clientStreamHeaders are the headers a client used to be able to switch its
// own deadlines off with. The first is the control: no header at all.
var clientStreamHeaders = []struct{ name, header string }{
	{"no_stream_header", ""},
	{"websocket_upgrade", "Upgrade: websocket\r\nConnection: Upgrade\r\n"},
	{"any_upgrade", "Upgrade: x\r\n"},
	{"event_stream_accept", "Accept: text/event-stream\r\n"},
}

// startDeadlineEP starts a plaintext HTTP entrypoint with epDeadline read and
// write timeouts in front of h, and returns its address.
func startDeadlineEP(t *testing.T, h http.Handler) string {
	t.Helper()
	deps := mockDepsForInspection(t)
	capture := &addrCapture{addrs: make(chan net.Addr, 1)}
	deps.Phantom = capture
	deps.BaseHandler = h
	ms := int32(epDeadline / time.Millisecond)
	ep := &gateonv1.EntryPoint{Id: "deadline", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP,
		ReadTimeoutMs: ms, WriteTimeoutMs: ms}
	wg := &syncutil.WaitGroup{}
	(&httpRunner{}).Run(context.Background(), ep, deps, wg)
	t.Cleanup(func() {
		ctx, cancel := contextWithBound()
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
	return (<-capture.addrs).String()
}

// contextWithBound is the window a test's servers get to shut down in.
func contextWithBound() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), streamTestBound)
}

// dialEP opens a connection to addr that the test closes when it ends.
func dialEP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, streamTestBound)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// bodyReadingHandler reads the whole request body and reports how that ended.
func bodyReadingHandler(result chan<- error) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		result <- err
	})
}

// writingHandler writes 64 MiB, far more than any socket buffer holds, and
// reports how that ended.
func writingHandler(result chan<- error) http.Handler {
	chunk := make([]byte, 32<<10)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 2048 {
			if _, err := w.Write(chunk); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	})
}

// endedWithError waits for a handler's report and fails unless it was an error
// that arrived within streamTestBound.
func endedWithError(t *testing.T, result <-chan error, what string) {
	t.Helper()
	select {
	case err := <-result:
		if err == nil {
			t.Fatalf("%s finished, but the client never sent or read it all", what)
		}
	case <-time.After(streamTestBound):
		t.Fatalf("%s was still in progress %v later: the %v entrypoint deadline was not applied", what, streamTestBound, epDeadline)
	}
}

// TestASlowBodyIsCutAtTheReadDeadlineWhateverItsHeaders: a request body sent
// one byte and then nothing is cut at the entrypoint's read deadline, with or
// without a header naming a stream. Any Upgrade header, or an Accept naming
// text/event-stream, used to remove both deadlines, so the client chose its own
// timeout -- none -- on any route.
func TestASlowBodyIsCutAtTheReadDeadlineWhateverItsHeaders(t *testing.T) {
	for _, tc := range clientStreamHeaders {
		t.Run(tc.name, func(t *testing.T) {
			result := make(chan error, 1)
			addr := startDeadlineEP(t, bodyReadingHandler(result))
			c := dialEP(t, addr)
			req := "POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Length: 100000\r\n" + tc.header + "\r\nA"
			if _, err := io.WriteString(c, req); err != nil {
				t.Fatalf("write request: %v", err)
			}
			endedWithError(t, result, "a 100000-byte body sent one byte at a time")
		})
	}
}

// TestASlowReaderIsCutAtTheWriteDeadlineWhateverItsHeaders: a client that
// never reads its response is cut at the write deadline, whatever it asked for.
func TestASlowReaderIsCutAtTheWriteDeadlineWhateverItsHeaders(t *testing.T) {
	for _, tc := range clientStreamHeaders {
		t.Run(tc.name, func(t *testing.T) {
			result := make(chan error, 1)
			addr := startDeadlineEP(t, writingHandler(result))
			c := dialEP(t, addr)
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetReadBuffer(4096)
			}
			req := "GET /big HTTP/1.1\r\nHost: app.example\r\n" + tc.header + "\r\n"
			if _, err := io.WriteString(c, req); err != nil {
				t.Fatalf("write request: %v", err)
			}
			endedWithError(t, result, "a 64 MiB response to a client that reads nothing")
		})
	}
}

// TestASlowH2StreamIsCutWhateverItsAccept is the HTTP/2 half: Upgrade is not
// a legal HTTP/2 header, but Accept is, and it lifted the deadlines of the
// stream it was sent on.
func TestASlowH2StreamIsCutWhateverItsAccept(t *testing.T) {
	for _, accept := range []string{"", "text/event-stream"} {
		t.Run("accept="+accept, func(t *testing.T) {
			t.Run("slow_body", func(t *testing.T) {
				result := make(chan error, 1)
				addr := startDeadlineEP(t, bodyReadingHandler(result))
				pr, pw := io.Pipe()
				req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/upload", pr)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				req.Header.Set("Accept", accept)
				done := doInBackground(t, h2cClient(t), req, nil)
				t.Cleanup(func() { _ = pw.CloseWithError(errors.New("test over")); <-done })
				if _, err := pw.Write([]byte("A")); err != nil {
					t.Fatalf("write first byte: %v", err)
				}
				endedWithError(t, result, "an HTTP/2 request body sent one byte at a time")
			})
			t.Run("slow_read", func(t *testing.T) {
				result := make(chan error, 1)
				addr := startDeadlineEP(t, writingHandler(result))
				req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/big", nil)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				req.Header.Set("Accept", accept)
				// The response is never read: flow control stalls the handler.
				held := make(chan *http.Response, 1)
				done := doInBackground(t, h2cClient(t), req, held)
				t.Cleanup(func() {
					select {
					case resp := <-held:
						_ = resp.Body.Close()
					default:
					}
					<-done
				})
				endedWithError(t, result, "an HTTP/2 response to a client that reads nothing")
			})
		})
	}
}

// TestASlowHTTP3BodyIsCut: requests over HTTP/3 had no per-request deadline
// at all -- the QUIC server was handed the entrypoint's handler without them
// -- so a body sent one byte now and then was bounded only by the
// connection's idle timeout, which each byte reset.
func TestASlowHTTP3BodyIsCut(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	result := make(chan error, 1)
	deps.BaseHandler = bodyReadingHandler(result)
	ms := int32(epDeadline / time.Millisecond)
	ep := &gateonv1.EntryPoint{Id: "h3-deadline", Address: freeTCPAndUDPAddr(t), Type: gateonv1.EntryPoint_HTTP3,
		Tls: &gateonv1.TlsConfig{Enabled: true}, ReadTimeoutMs: ms, WriteTimeoutMs: ms}
	addr := httpEntrypointFor(t, ep, deps)

	tr := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() { _ = tr.Close() })
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/upload", pr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	done := doInBackground(t, &http.Client{Transport: tr}, req, nil)
	t.Cleanup(func() { _ = pw.CloseWithError(errors.New("test over")); <-done })
	if _, err := pw.Write([]byte("A")); err != nil {
		t.Fatalf("write first byte: %v", err)
	}
	endedWithError(t, result, "an HTTP/3 request body sent one byte at a time")
}

// doInBackground sends req on its own goroutine, which the returned channel
// says has finished. A response is handed to held unread, or closed when held
// is nil.
func doInBackground(t *testing.T, c *http.Client, req *http.Request, held chan<- *http.Response) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := c.Do(req)
		if err != nil {
			return
		}
		if held != nil {
			held <- resp
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return done
}

// eventStream answers as a server-sent-event stream: n events, gap apart,
// then it holds the stream open until the request ends. ended receives when
// the handler stopped.
func eventStream(n int, gap time.Duration, ended chan<- time.Time) http.Handler {
	return eventStreamThen(n, gap, ended, true)
}

// finiteEventStream is eventStream that ends the response after its events.
func finiteEventStream(n int, gap time.Duration, ended chan<- time.Time) http.Handler {
	return eventStreamThen(n, gap, ended, false)
}

func eventStreamThen(n int, gap time.Duration, ended chan<- time.Time, hold bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { ended <- time.Now() }()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		if rc.Flush() != nil {
			return
		}
		tick := time.NewTicker(gap)
		defer tick.Stop()
		for i := range n {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
			if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil || rc.Flush() != nil {
				return
			}
		}
		if hold {
			<-r.Context().Done()
		}
	})
}

// streamClients are the two ways a stream reaches a cleartext entrypoint.
func streamClients(t *testing.T) map[string]*http.Client {
	t.Helper()
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	return map[string]*http.Client{"http1": {Transport: tr}, "h2c": h2cClient(t)}
}

// readEvents opens an event stream and reads it until it ends or
// streamTestBound passes. It returns how many events arrived, when the last
// one did, and whether the stream ended (rather than still being open).
func readEvents(t *testing.T, c *http.Client, url string, hdr http.Header) (events int, last time.Time, ended bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), streamTestBound)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			events++
			last = time.Now()
		}
	}
	return events, last, ctx.Err() == nil
}

// TestAnEventStreamOutlivesTheRequestDeadlines: a response the server answers
// as text/event-stream keeps streaming past the entrypoint's deadlines, whether
// or not the client said it wanted one. It used to depend on the client's
// Accept header: without it, a real event stream was cut at the write deadline.
func TestAnEventStreamOutlivesTheRequestDeadlines(t *testing.T) {
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			const want = 16 // 16 x 60ms is three times the deadline
			addr := startDeadlineEP(t, finiteEventStream(want, 60*time.Millisecond, ended))
			got, _, _ := readEvents(t, client, "http://"+addr+"/events", nil)
			if got != want {
				t.Fatalf("received %d of %d events: the stream was cut at the %v request deadline", got, want, epDeadline)
			}
		})
	}
}

// TestAnEventStreamIsClosedOnceIdle: a stream that goes quiet is closed by the
// idle timeout. With an Accept header the stream used to have no deadline of
// any kind, so a quiet one was held for as long as the client stayed.
func TestAnEventStreamIsClosedOnceIdle(t *testing.T) {
	const idle = 700 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", idle.String())
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			const want = 8 // 8 x 100ms is past the request deadline
			addr := startDeadlineEP(t, eventStream(want, 100*time.Millisecond, ended))
			got, last, closed := readEvents(t, client, "http://"+addr+"/events",
				http.Header{"Accept": {"text/event-stream"}})
			if got != want {
				t.Fatalf("received %d of %d events before the stream went quiet", got, want)
			}
			if !closed {
				t.Fatalf("the stream was still open %v after it went quiet: no idle timeout", streamTestBound)
			}
			if quiet := time.Since(last); quiet < idle/2 {
				t.Fatalf("the stream closed %v after its last event, well inside the %v idle timeout", quiet, idle)
			}
			handlerEnded(t, ended)
		})
	}
}

// TestAnEventStreamEndsAtItsMaxLifetime: a stream that never goes quiet still
// ends at its maximum lifetime.
func TestAnEventStreamEndsAtItsMaxLifetime(t *testing.T) {
	const lifetime = 900 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", lifetime.String())
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			addr := startDeadlineEP(t, eventStream(1000, 50*time.Millisecond, ended))
			start := time.Now()
			got, _, closed := readEvents(t, client, "http://"+addr+"/events",
				http.Header{"Accept": {"text/event-stream"}})
			if !closed {
				t.Fatalf("a busy stream was still open %v after it started: no maximum lifetime", streamTestBound)
			}
			if took := time.Since(start); took < lifetime*3/4 {
				t.Fatalf("the stream ended after %v (%d events), before its %v lifetime", took, got, lifetime)
			}
			handlerEnded(t, ended)
		})
	}
}

// handlerEnded fails unless the stream's handler stopped: a stream closed to
// the client but still served would hold the gateway's side all the same.
func handlerEnded(t *testing.T, ended <-chan time.Time) {
	t.Helper()
	select {
	case <-ended:
	case <-time.After(streamTestBound):
		t.Fatal("the client's stream ended but its handler is still running")
	}
}

// echoUpgradeBackend answers any request with 101 and then echoes every byte
// back until the gateway closes its side.
func echoUpgradeBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { echoUpgrade(c) })
		}
	})
	return ln.Addr().String()
}

func echoUpgrade(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * streamTestBound))
	br := bufio.NewReader(c)
	if _, err := http.ReadRequest(br); err != nil {
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	_, _ = io.Copy(c, br)
}

// silentBackendAddr accepts connections and reads them, and never answers.
func silentBackendAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * streamTestBound))
				_, _ = io.Copy(io.Discard, c)
			})
		}
	})
	return ln.Addr().String()
}

// proxyTo is a ProxyHandler with one route to backend.
func proxyTo(t *testing.T, backend string) http.Handler {
	t.Helper()
	services := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: "http://" + backend, Weight: 1}},
	}); err != nil {
		t.Fatalf("service: %v", err)
	}
	ph := proxy.NewProxyHandler(&gateonv1.Route{Id: "ws", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http"}, services)
	t.Cleanup(ph.Close)
	return ph
}

// upgradeThrough sends a WebSocket upgrade to addr and returns the connection
// and its reader once the 101 has been read.
func upgradeThrough(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c := dialEP(t, addr)
	req := "GET /ws HTTP/1.1\r\nHost: app.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	// A 101 has no body; this closes the Body only, not the tunnel.
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade answered %d, want 101", resp.StatusCode)
	}
	return c, br
}

// TestAWebSocketOutlivesTheRequestDeadlinesAndEndsWhenIdle: a real upgrade,
// answered 101 by its backend, carries traffic past the entrypoint's
// deadlines and is closed by the idle timeout once nothing moves. The tunnel
// used to have no idle timeout at all.
func TestAWebSocketOutlivesTheRequestDeadlinesAndEndsWhenIdle(t *testing.T) {
	const idle = 700 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", idle.String())
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	addr := startDeadlineEP(t, proxyTo(t, echoUpgradeBackend(t)))
	c, br := upgradeThrough(t, addr)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for i := range 10 { // 10 x 100ms is past the request deadline
		<-tick.C
		msg := fmt.Sprintf("ping-%d\n", i)
		if _, err := io.WriteString(c, msg); err != nil {
			t.Fatalf("write %q through the tunnel: %v", msg, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
		got, err := br.ReadString('\n')
		if err != nil || got != msg {
			t.Fatalf("echo of %q = %q, %v: the tunnel was cut at the %v request deadline", msg, got, err, epDeadline)
		}
	}
	last := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
	b, err := br.ReadByte()
	if isTimeout(err) {
		t.Fatalf("the tunnel was still open %v after it went quiet: no idle timeout", streamTestBound)
	}
	if err == nil {
		t.Fatalf("read %q from a tunnel nobody wrote to", b)
	}
	if quiet := time.Since(last); quiet < idle/2 {
		t.Fatalf("the tunnel closed %v after its last byte, well inside the %v idle timeout", quiet, idle)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestAnUpgradeTheBackendNeverAnswersIsCut: an Upgrade request whose backend
// never answers is ended, not held. It used to have no deadline on the client
// side and none on the backend's answer, so it was held until the client left.
func TestAnUpgradeTheBackendNeverAnswersIsCut(t *testing.T) {
	addr := startDeadlineEP(t, proxyTo(t, silentBackendAddr(t)))
	c := dialEP(t, addr)
	req := "GET /ws HTTP/1.1\r\nHost: app.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if isTimeout(err) {
		t.Fatalf("an upgrade the backend never answered was still held %v later", streamTestBound)
	}
	if err != nil {
		return // closed without an answer: ended, which is the point
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 500 {
		t.Fatalf("an upgrade the backend never answered was answered %d", resp.StatusCode)
	}
}

// TestAnOversizedHeaderIsRefusedWith431: a request header past the cap is
// refused before it is buffered, and one well inside it is served. The cap was
// 1 MiB per connection, which at the minimal tier's 1000 connections is more
// memory than the 2 GB host has.
func TestAnOversizedHeaderIsRefusedWith431(t *testing.T) {
	t.Setenv("GATEON_MAX_HEADER_BYTES", "")
	addr := startDeadlineEP(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	if code := headerStatus(t, addr, 8<<10); code != http.StatusOK {
		t.Fatalf("an 8 KiB header was answered %d, want 200", code)
	}
	if code := headerStatus(t, addr, 40<<10); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a 40 KiB header was answered %d, want 431", code)
	}
	t.Run("h2c", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		// 48 KiB in fields of 8 KiB: a list modestly past the cap is answered
		// 431. Far past it -- or one field past it -- net/http's HTTP/2 server
		// closes the connection instead (its CONTINUATION-flood and HPACK
		// guards), which refuses it all the same.
		for i := range 6 {
			req.Header.Set(fmt.Sprintf("X-Big-%d", i), strings.Repeat("a", 8<<10))
		}
		resp, err := h2cClient(t).Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("a 48 KiB HTTP/2 header list was answered %d, want 431", resp.StatusCode)
			}
		} else if !strings.Contains(err.Error(), "larger than peer's advertised limit") {
			t.Fatalf("a 48 KiB HTTP/2 header list failed with %v, want 431 or the server's advertised limit", err)
		}
	})
}

// headerStatus sends one request with a header value of n bytes and returns
// the status it was answered with.
func headerStatus(t *testing.T, addr string, n int) int {
	t.Helper()
	c := dialEP(t, addr)
	req := "GET / HTTP/1.1\r\nHost: app.example\r\nX-Big: " + strings.Repeat("a", n) + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response to a %d-byte header: %v", n, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
