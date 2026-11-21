// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/server/entrypoint/connguard"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// guardedEntrypoint serves handler on a loopback port through the listener
// and guard an HTTP entrypoint uses, with room for slots connections.
func guardedEntrypoint(t *testing.T, slots int, unproven *connguard.Unproven, resets int, handler http.Handler) (string, *connSlots) {
	t.Helper()
	ep := &gateonv1.EntryPoint{Id: "guard", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP, MaxConnections: int32(slots)}
	e := &httpEntrypoint{ep: ep, slots: newConnSlots(ep), unproven: unproven, h2Resets: resets}
	server := e.newServer(guardRequests(handler))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &cappedListener{Listener: ln, slots: e.slots, unproven: e.unproven, h2Resets: e.h2Resets}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String(), e.slots
}

// waitHeld spins until n slots are held, so the test knows the accept loop has
// taken every connection it dialled.
func waitHeld(t *testing.T, s *connSlots, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.held.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("held %d slots, want %d", s.held.Load(), n)
		}
		runtime.Gosched()
	}
}

func ok(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }

// fillWithSilentConnections opens n TCP connections that send nothing.
func fillWithSilentConnections(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, n)
	for i := range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns[i] = c
	}
	return conns
}

func freshGet(addr string) error {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// Connections that send nothing filled every slot, and a full entrypoint
// refused the newcomer: in the 2026-11-13 lab, sixty addresses doing that
// failed 183 of 189 real requests (review D1). Root cause: a connection that
// had proved nothing counted the same as one serving requests, and the one
// refused was the newest. With the guard, the oldest silent connection is
// closed to admit the newcomer.
func TestSilentConnectionsCannotFillAnEntrypoint(t *testing.T) {
	t.Run("without the guard the newcomer is refused", func(t *testing.T) {
		addr, slots := guardedEntrypoint(t, 4, nil, 0, http.HandlerFunc(ok))
		fillWithSilentConnections(t, addr, 4)
		waitHeld(t, slots, 4)
		if err := freshGet(addr); err == nil {
			t.Fatal("the request got through a full entrypoint; the scenario does not reproduce")
		}
	})
	t.Run("with the guard the oldest silent connection makes way", func(t *testing.T) {
		addr, slots := guardedEntrypoint(t, 4, connguard.NewUnproven(16, time.Hour, time.Hour), 0, http.HandlerFunc(ok))
		silent := fillWithSilentConnections(t, addr, 4)
		waitHeld(t, slots, 4)
		if err := freshGet(addr); err != nil {
			t.Fatalf("a request to a full entrypoint failed: %v", err)
		}
		_ = silent[0].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := silent[0].Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("the oldest silent connection: read %v, want it closed", err)
		}
	})
}

// A connection that has delivered a request is proven and is never the one
// evicted, however long it then idles between keep-alive requests.
func TestAProvenConnectionIsNotEvicted(t *testing.T) {
	addr, slots := guardedEntrypoint(t, 2, connguard.NewUnproven(16, time.Hour, time.Hour), 0, http.HandlerFunc(ok))
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}, Timeout: 5 * time.Second}
	get := func() error {
		resp, err := client.Get("http://" + addr + "/")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	fillWithSilentConnections(t, addr, 1)
	waitHeld(t, slots, 2)
	if err := freshGet(addr); err != nil { // evicts the silent one
		t.Fatalf("newcomer refused: %v", err)
	}
	if err := get(); err != nil {
		t.Fatalf("the proven keep-alive connection was closed: %v", err)
	}
}

// rapidReset opens an h2c connection and opens and cancels n streams on it,
// as CVE-2023-44487 does. It reports whether the server closed the connection
// or told the client to go away, rather than answering a PING after them.
func rapidReset(t *testing.T, addr string, n int) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", addr}} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	// The one reader: it reports true when the server closes the connection
	// or sends GOAWAY, false when it acknowledges the final PING.
	closed := make(chan bool, 1)
	go func() {
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				closed <- true
				return
			}
			switch f := f.(type) {
			case *http2.GoAwayFrame:
				closed <- true
				return
			case *http2.PingFrame:
				if f.IsAck() && f.Data == [8]byte{7} {
					closed <- false
					return
				}
			}
		}
	}()
	for i := range n {
		id := uint32(2*i + 1)
		if fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: true}) != nil ||
			fr.WriteRSTStream(id, http2.ErrCodeCancel) != nil {
			return true // the server closed the connection
		}
	}
	if fr.WritePing(false, [8]byte{7}) != nil {
		return true
	}
	return <-closed
}

// slowHandler holds each request until its client goes away, as a backend
// that has not answered yet does.
func slowHandler(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

// A client opening and cancelling streams faster than any browser kept 128
// connections' worth of handlers busy and took the 2 GB host to its memory
// limit (review D2). Root cause: net/http bounds how many streams run at once,
// not how fast they are opened and reset. The guard closes such a connection.
func TestRapidResetClosesTheConnection(t *testing.T) {
	addr, _ := guardedEntrypoint(t, 16, nil, 50, http.HandlerFunc(slowHandler))
	if !rapidReset(t, addr, 5000) {
		t.Fatal("a connection that opened and reset 5,000 streams was kept open")
	}
}

// A client that cancels a few streams, as a browser leaving a page does, keeps
// its connection.
func TestAFewCancelledStreamsKeepTheConnection(t *testing.T) {
	addr, _ := guardedEntrypoint(t, 16, nil, 50, http.HandlerFunc(slowHandler))
	if rapidReset(t, addr, 10) {
		t.Fatal("a connection that cancelled ten streams was closed")
	}
}

// Closing a rapid-reset connection bounded memory but not CPU: in the
// 2026-11-17 lab the 128 attacking connections reconnected at once, the
// gateway kept parsing two million frames a second, and a legitimate client
// waited 2.7 s at the median. net/http closed nine in ten of them itself,
// with ENHANCE_YOUR_CALM, before the reset count saw enough. Root cause: a
// close is free to undo. An address whose connection is closed either way now
// cools off, refused at accept.
func TestTheServersCalmCloseStartsACoolOff(t *testing.T) {
	ep := &gateonv1.EntryPoint{Id: "calm", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP, MaxConnections: 16}
	cool := connguard.NewCoolOff(time.Minute, 8)
	e := &httpEntrypoint{ep: ep, slots: newConnSlots(ep), coolOff: cool}
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	// Handlers that ignore cancellation keep every stream slot busy, so the
	// streams after them queue, which is what net/http refuses with
	// ENHANCE_YOUR_CALM. The reset count is off: only net/http closes here.
	server := e.newServer(guardRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-stuck })))
	// Loopback is exempt in production; key it here as any other address.
	server.ErrorLog.SetOutput(cool.WatchServerErrors(io.Discard, connKey))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &cappedListener{Listener: ln, slots: e.slots, coolOff: cool}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })

	if !rapidReset(t, ln.Addr().String(), 5000) {
		t.Fatal("net/http kept a connection that queued 5,000 streams")
	}
	if !cool.Refuses(netip.MustParseAddr("127.0.0.1"), time.Now()) {
		t.Fatal("the address net/http closed for ENHANCE_YOUR_CALM is not cooling off")
	}
	if freshGet(ln.Addr().String()) == nil {
		t.Fatal("a cooling-off address was served")
	}
}

// The reset guard's own close starts the cool-off too.
func TestTheResetGuardsCloseStartsACoolOff(t *testing.T) {
	ep := &gateonv1.EntryPoint{Id: "reset", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP, MaxConnections: 16}
	cool := connguard.NewCoolOff(time.Minute, 8)
	sc := &slotConn{Conn: nopConn{}, slots: newConnSlots(ep), addr: "10.0.0.7", coolOff: cool}
	sc.resets.Init(1)
	sc.noteReset()
	sc.noteReset()
	if !cool.Refuses(netip.MustParseAddr("10.0.0.7"), time.Now()) {
		t.Fatal("the address the reset guard closed is not cooling off")
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }
