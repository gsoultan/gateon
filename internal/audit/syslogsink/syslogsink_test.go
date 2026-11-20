// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package syslogsink

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
)

// receiver is a TCP syslog receiver that reads octet-counted frames.
type receiver struct {
	ln     net.Listener
	frames chan string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &receiver{ln: ln, frames: make(chan string, 64)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.read(c)
		}
	}()
	return r
}

func (r *receiver) read(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		r.frames <- string(buf)
	}
}

func (r *receiver) next(t *testing.T) string {
	t.Helper()
	select {
	case f := <-r.frames:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver got nothing")
		return ""
	}
}

func start(t *testing.T, cfg Config) *Forwarder {
	t.Helper()
	f := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	t.Cleanup(func() { cancel(); <-f.Done() })
	return f
}

func body(t *testing.T, frame string) map[string]any {
	t.Helper()
	i := strings.Index(frame, " audit - ")
	if i < 0 {
		t.Fatalf("frame %q has no audit MSGID", frame)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(frame[i+len(" audit - "):]), &m); err != nil {
		t.Fatalf("frame body: %v", err)
	}
	return m
}

// The copy that leaves the host carries every field the chain signs, so it
// can be verified on its own against the log the attacker may have rewritten.
func TestAnEntryReachesTheReceiverVerifiable(t *testing.T) {
	r := newReceiver(t)
	f := start(t, Config{Network: "tcp", Address: r.ln.Addr().String(), Hostname: "gw-1"})
	ts := time.Date(2026, 11, 17, 4, 0, 0, 0, time.UTC)
	f.Sink(audit.AuditEntry{ID: "e1", UserID: "admin", Action: "delete", Resource: "user",
		Details: "Deleted user 7\nwith a newline", Timestamp: ts, IPAddress: "192.0.2.1",
		Signature: "sig-1", PreviousHash: "sig-0"})

	frame := r.next(t)
	if !strings.HasPrefix(frame, "<109>1 2026-11-17T04:00:00Z gw-1 gateon - audit - ") {
		t.Fatalf("frame header = %q, want facility log-audit, severity notice, RFC 5424", frame)
	}
	m := body(t, frame)
	for k, want := range map[string]string{
		"id": "e1", "userId": "admin", "action": "delete", "resource": "user",
		"details": "Deleted user 7\nwith a newline", "signature": "sig-1", "previousHash": "sig-0",
		"ipAddress": "192.0.2.1",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %q", k, m[k], want)
		}
	}
}

// A flood of system entries -- one per blocked request, at the attacker's
// rate -- must not decide which of an administrator's entries is dropped.
func TestAnAccountsEntryIsNotCrowdedOutBySystemEntries(t *testing.T) {
	f := New(Config{Network: "tcp", Address: "127.0.0.1:1"}) // not run: queues fill
	for range bulkQueue + 500 {
		f.Sink(audit.AuditEntry{UserID: "system", Action: "waf_block"})
	}
	f.Sink(audit.AuditEntry{UserID: "admin", Action: "update", Resource: "user"})
	q, ok := f.next(context.Background())
	if !ok || q.e.UserID != "admin" {
		t.Fatalf("next = %+v, want the administrator's entry first", q.e)
	}
	if f.drops.Load() != 500 {
		t.Fatalf("dropped %d system entries, want 500 counted", f.drops.Load())
	}
}

// A long details field is cut, bounded in memory, and the copy says it was.
func TestLongDetailsAreCutAndMarked(t *testing.T) {
	r := newReceiver(t)
	f := start(t, Config{Network: "tcp", Address: r.ln.Addr().String(), Hostname: "gw"})
	f.Sink(audit.AuditEntry{UserID: "system", Action: "waf_block", Details: strings.Repeat("a", maxDetails*3)})
	m := body(t, r.next(t))
	if d, _ := m["details"].(string); len(d) != maxDetails {
		t.Fatalf("details length %d, want %d", len(d), maxDetails)
	}
	if m["detailsTruncated"] != true {
		t.Fatal("a cut entry is not marked as cut")
	}
}

// A receiver that goes away and comes back gets the entry that failed, on the
// next connection, rather than a silent gap.
func TestAFailedWriteIsSentAgainAfterReconnecting(t *testing.T) {
	r := newReceiver(t)
	fails := 1
	f := New(Config{Network: "tcp", Address: r.ln.Addr().String(), Hostname: "gw"})
	f.dial = func(ctx context.Context) (net.Conn, error) {
		c, err := f.dialReceiver(ctx)
		if err == nil && fails > 0 {
			fails--
			_ = c.Close() // the first connection is dead before the write
		}
		return c, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	t.Cleanup(func() { cancel(); <-f.Done() })
	f.Sink(audit.AuditEntry{ID: "kept", UserID: "admin", Action: "update", Resource: "user"})
	if m := body(t, r.next(t)); m["id"] != "kept" {
		t.Fatalf("got %v, want the entry whose first write failed", m["id"])
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvAddr, "")
	if _, ok, err := ConfigFromEnv(); ok || err != nil {
		t.Fatalf("unset: ok=%v err=%v, want not configured", ok, err)
	}
	for _, bad := range []string{"logs.example:514", "http://logs.example:514", "tcp://logs.example", "tls://"} {
		t.Setenv(EnvAddr, bad)
		if _, ok, err := ConfigFromEnv(); !ok || err == nil {
			t.Errorf("%q: ok=%v err=%v, want an error, not silence", bad, ok, err)
		}
	}
	t.Setenv(EnvAddr, "tls://logs.example:6514")
	t.Setenv(EnvCAFile, "")
	cfg, ok, err := ConfigFromEnv()
	if err != nil || !ok || cfg.Network != "tls" || cfg.TLS == nil || cfg.TLS.ServerName != "logs.example" {
		t.Fatalf("tls config = %+v ok=%v err=%v", cfg, ok, err)
	}
	t.Setenv(EnvCAFile, "/nonexistent/ca.pem")
	if _, _, err := ConfigFromEnv(); err == nil {
		t.Fatal("an unreadable CA file was accepted")
	}
}
