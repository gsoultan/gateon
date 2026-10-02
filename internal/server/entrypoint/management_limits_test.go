// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/deadline"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// These tests pin the management listener's half of ADR 0042 (review finding
// M7): one address holding slow request bodies made the whole management port
// answer 503, its health check included, because the listener had no read
// timeout and no per-address connection cap.

// attacker is the one remote address the slow-body connections come from.
var attacker = &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}

// spoofFirst is a PhantomCore whose listener reports the first n connections
// it accepts as coming from one remote address, and every later one as
// itself. Dialled one after another, connections are accepted in the order
// they were dialled, so the test knows which is which.
type spoofFirst struct {
	addrs chan net.Addr
	n     int
	as    net.Addr
}

func (s *spoofFirst) OptimizeListener(l net.Listener) net.Listener {
	s.addrs <- l.Addr()
	return &spoofListener{Listener: l, left: s.n, as: s.as}
}

type spoofListener struct {
	net.Listener
	left int // only the server's accept loop touches it
	as   net.Addr
}

func (l *spoofListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || l.left == 0 {
		return c, err
	}
	l.left--
	return &spoofedConn{Conn: c, remote: l.as}, nil
}

type spoofedConn struct {
	net.Conn
	remote net.Addr
}

func (c *spoofedConn) RemoteAddr() net.Addr { return c.remote }

// startManagement starts the management listener in front of h, the first n
// connections to it appearing to come from attacker, and returns its address.
func startManagement(t *testing.T, n int, h http.Handler, timeouts *deadline.RequestTimeouts) string {
	t.Helper()
	t.Setenv("GATEON_PROFILE", "standard")
	t.Setenv("GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR", "")
	t.Setenv("GATEON_MANAGEMENT_ALLOWED_IPS", "0.0.0.0/0,::/0")
	for _, env := range []string{"GATEON_MANAGEMENT_BIND", "GATEON_MANAGEMENT_PORT", "GATEON_MANAGEMENT_HOST"} {
		t.Setenv(env, "")
	}
	deps := mockDepsForInspection(t)
	spoof := &spoofFirst{addrs: make(chan net.Addr, 1), n: n, as: attacker}
	deps.Phantom = spoof
	deps.BaseHandler = h
	deps.ManagementConfig = &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: "0"}
	deps.ManagementTimeouts = timeouts
	wg := &syncutil.WaitGroup{}
	startSecureManagementServer("0", deps, wg)
	t.Cleanup(func() {
		ctx, cancel := contextWithBound()
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
	return (<-spoof.addrs).String()
}

// slowVerify sends the review's probe: a POST to the public 2FA endpoint
// declaring a 100000-byte body and sending one byte of it.
func slowVerify(t *testing.T, c net.Conn) {
	t.Helper()
	req := "POST /v1/auth/2fa/verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n" +
		"Content-Length: 100000\r\n\r\n{"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write slow request: %v", err)
	}
}

// answeredOrClosed is closed once c has anything to read, or has been closed:
// the request was refused or answered, rather than taken in by the handler.
func answeredOrClosed(c net.Conn, wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	wg.Go(func() {
		defer close(done)
		_, _ = c.Read(make([]byte, 1))
	})
	return done
}

// TestTheManagementPortAnswersHealthWhileOneAddressHoldsSlowBodies is the
// review's probe: 510 connections from one address, each a slow body to the
// unauthenticated 2FA endpoint. The listener admitted every one and their
// requests filled the management chain's 500 in-flight slots, so /healthz --
// and everything else on the port -- answered 503 for as long as they were
// held.
func TestTheManagementPortAnswersHealthWhileOneAddressHoldsSlowBodies(t *testing.T) {
	const n = 510
	entered := make(chan struct{}, n)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		entered <- struct{}{}
		_, _ = io.Copy(io.Discard, r.Body)
	})
	addr := startManagement(t, n, h, nil)
	var readers sync.WaitGroup
	t.Cleanup(readers.Wait) // runs after every connection below is closed

	// Each connection is taken in by the handler, refused at accept, or held:
	// a request turned away by the in-flight cap is answered 503 only after
	// net/http has drained its body, which never comes. Held is the outcome
	// the fix rules out, and the health check below is what tells.
	for range n {
		c := dialEP(t, addr)
		slowVerify(t, c)
		select {
		case <-entered:
		case <-answeredOrClosed(c, &readers):
		case <-time.After(time.Second):
		}
	}

	c := dialEP(t, addr)
	if _, err := io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		t.Fatalf("write health check: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(streamTestBound))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz answered %d while %d slow-body connections from one address were held", resp.StatusCode, n)
	}
}

// shortManagementTimeouts are the management listener's bounds scaled down so
// a test can watch them work: the same mechanism production runs, at 300 ms.
func shortManagementTimeouts() *deadline.RequestTimeouts {
	return &deadline.RequestTimeouts{Read: epDeadline, Write: epDeadline, MinBodyRate: 32 << 10}
}

// TestAManagementSlowBodyIsCut: the listener had a header timeout and nothing
// else, so a body sent one byte at a time was read for as long as the client
// liked.
func TestAManagementSlowBodyIsCut(t *testing.T) {
	result := make(chan error, 1)
	addr := startManagement(t, 0, bodyReadingHandler(result), shortManagementTimeouts())
	slowVerify(t, dialEP(t, addr))
	endedWithError(t, result, "a management request body sent one byte at a time")
}

// sendPaced sends total bytes of body to c in chunks of chunk bytes, one per
// gap, after a request head declaring that length.
func sendPaced(c net.Conn, total, chunk int, gap time.Duration) {
	head := fmt.Sprintf("POST /v1/geoip/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %d\r\n\r\n", total)
	if _, err := io.WriteString(c, head); err != nil {
		return
	}
	tick := time.NewTicker(gap)
	defer tick.Stop()
	buf := make([]byte, chunk)
	for sent := 0; sent < total; sent += chunk {
		<-tick.C
		if _, err := c.Write(buf); err != nil {
			return // cut: the handler's report says why
		}
	}
}

// TestAManagementUploadIsBoundedByProgressNotByATotal: a body that keeps up
// the minimum rate is read to the end, however long past the read timeout
// that takes -- a GeoIP database over a slow link -- and one that falls
// behind it is cut, however steadily it trickles.
func TestAManagementUploadIsBoundedByProgressNotByATotal(t *testing.T) {
	t.Run("keeps_up", func(t *testing.T) {
		result := make(chan error, 1)
		addr := startManagement(t, 0, bodyReadingHandler(result), shortManagementTimeouts())
		// 160 KiB at 80 KiB/s: two seconds, six times the read timeout.
		sendPaced(dialEP(t, addr), 160<<10, 8<<10, 100*time.Millisecond)
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("an upload keeping up 80 KiB/s against a 32 KiB/s floor was cut: %v", err)
			}
		case <-time.After(streamTestBound):
			t.Fatal("the upload never finished")
		}
	})
	t.Run("falls_behind", func(t *testing.T) {
		result := make(chan error, 1)
		addr := startManagement(t, 0, bodyReadingHandler(result), shortManagementTimeouts())
		c := dialEP(t, addr)
		var wg sync.WaitGroup
		t.Cleanup(func() { _ = c.Close(); wg.Wait() })
		// 1 KiB every 100ms is 10 KiB/s, under the 32 KiB/s floor.
		wg.Go(func() { sendPaced(c, 100<<10, 1<<10, 100*time.Millisecond) })
		endedWithError(t, result, "an upload trickling 10 KiB/s against a 32 KiB/s floor")
	})
}

// TestAManagementEventStreamOutlivesTheRequestTimeouts: the dashboard's event
// streams are lifted to the stream bounds, so the read and write timeouts
// that now bound every other management request do not cut them.
func TestAManagementEventStreamOutlivesTheRequestTimeouts(t *testing.T) {
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	for name, client := range streamClients(t) {
		t.Run(name, func(t *testing.T) {
			ended := make(chan time.Time, 1)
			const want = 16
			addr := startManagement(t, 0, finiteEventStream(want, 60*time.Millisecond, ended), shortManagementTimeouts())
			got, _, _ := readEvents(t, client, "http://"+addr+"/v1/watch", nil)
			if got != want {
				t.Fatalf("received %d of %d events: the management stream was cut at its request timeouts", got, want)
			}
		})
	}
}

// TestTheManagementListenerRefusesAnOversizedHeader: the management listener
// buffered 1 MiB of header per connection too.
func TestTheManagementListenerRefusesAnOversizedHeader(t *testing.T) {
	t.Setenv("GATEON_MAX_HEADER_BYTES", "")
	addr := startManagement(t, 0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), nil)
	if code := headerStatus(t, addr, 40<<10); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a 40 KiB header to the management listener was answered %d, want 431", code)
	}
}
