// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	redigo "github.com/redis/go-redis/v9"
)

// publishRedis is the smallest redis.Client that can stand in for the broker:
// only Publish is implemented, and the embedded nil Cmdable would panic if the
// code under test reached for anything else.
type publishRedis struct {
	redigo.Cmdable
	mu   sync.Mutex
	sent [][]byte
	err  error
}

func (p *publishRedis) Publish(ctx context.Context, _ string, message any) *redigo.IntCmd {
	p.mu.Lock()
	if b, ok := message.([]byte); ok {
		p.sent = append(p.sent, append([]byte(nil), b...))
	}
	p.mu.Unlock()
	cmd := redigo.NewIntCmd(ctx)
	if p.err != nil {
		cmd.SetErr(p.err)
	}
	return cmd
}

func (p *publishRedis) Subscribe(context.Context, ...string) *redigo.PubSub { return nil }
func (p *publishRedis) Close() error                                        { return nil }

func (p *publishRedis) messages() []InvalidationMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]InvalidationMessage, 0, len(p.sent))
	for _, raw := range p.sent {
		var m InvalidationMessage
		if err := json.Unmarshal(raw, &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// countingInvalidator records that the local half ran.
type countingInvalidator struct {
	routes, routeSets, tls, waf int
}

func (c *countingInvalidator) InvalidateRoute(string)                      { c.routes++ }
func (c *countingInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) { c.routeSets++ }
func (c *countingInvalidator) InvalidateTLS()                              { c.tls++ }
func (c *countingInvalidator) InvalidateWAF()                              { c.waf++ }

// captureLogs empties logger.L's shim, so it falls through to slog's default,
// which this swaps for a buffer. The buffer is locked: a request or loop an
// earlier test started can still be logging while this test reads it.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	var buf syncBuffer

	prevInner := logger.L.Swap(nil)
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	t.Cleanup(func() {
		logger.L.Swap(prevInner)
		slog.SetDefault(prevDefault)
	})
	return &buf
}

// syncBuffer is a bytes.Buffer safe to write from other goroutines while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestInvalidationPublishFailureIsReported closes a silent failure on the
// cluster's only config-convergence mechanism.
//
// The four invalidators discarded the Publish result entirely, while the
// session-revocation publisher in the same file checked it. A broker that
// refused the message therefore left every peer serving the superseded value
// with nothing logged -- and unlike a session binding, which expires at
// DefaultBindingTTL whatever happens, nothing re-converges a config cache. The
// registries load once at construction; there is no periodic reload. For
// InvalidateTLS, called after a certificate is replaced, the peers keep
// serving the old certificate until they restart.
func TestInvalidationPublishFailureIsReported(t *testing.T) {
	buf := captureLogs(t)

	local := &countingInvalidator{}
	broker := &publishRedis{err: errors.New("broker unreachable")}
	inv := NewDistributedProxyInvalidator(local, broker)

	inv.InvalidateTLS()

	if local.tls != 1 {
		t.Errorf("local invalidation ran %d times, want 1; it must happen "+
			"regardless of the broker", local.tls)
	}
	if got := buf.String(); !strings.Contains(got, "not propagated") {
		t.Errorf("a failed invalidation publish was not reported; peers keep the "+
			"superseded value and nothing says so. log was: %s", got)
	}
}

// TestInvalidationPublishesTheRightType pins the wiring. InvalidateRoutes takes
// a strategy function, which cannot cross the wire, so it must broadcast "all"
// rather than a per-route message: over-invalidating costs peers a rebuild,
// under-invalidating leaves them serving a route the operator deleted.
func TestInvalidationPublishesTheRightType(t *testing.T) {
	local := &countingInvalidator{}
	broker := &publishRedis{}
	inv := NewDistributedProxyInvalidator(local, broker)

	inv.InvalidateRoute("route-7")
	inv.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
	inv.InvalidateTLS()
	inv.InvalidateWAF()

	got := broker.messages()
	if len(got) != 4 {
		t.Fatalf("published %d messages, want 4: %+v", len(got), got)
	}
	want := []struct{ typ, id string }{
		{"route", "route-7"}, {"all", ""}, {"tls", ""}, {"waf", ""},
	}
	for i, w := range want {
		if got[i].Type != w.typ || got[i].ID != w.id {
			t.Errorf("message %d = {Type:%q ID:%q}, want {Type:%q ID:%q}",
				i, got[i].Type, got[i].ID, w.typ, w.id)
		}
		if got[i].NodeID == "" {
			t.Errorf("message %d carries no NodeID; the listener drops its own echo "+
				"by comparing it, so an empty one makes every node apply its own message", i)
		}
	}
}

// A single-node deployment has no broker. Publishing must be skipped, not
// attempted against a nil client.
func TestInvalidationWithoutBrokerStillInvalidatesLocally(t *testing.T) {
	local := &countingInvalidator{}
	inv := NewDistributedProxyInvalidator(local, nil)

	inv.InvalidateRoute("r")
	inv.InvalidateTLS()

	if local.routes != 1 || local.tls != 1 {
		t.Errorf("local invalidation did not run without a broker: %+v", local)
	}
}
