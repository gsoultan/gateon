// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"testing"

	"github.com/gsoultan/gateon/pkg/l4"
)

// TestAServerFirstSessionIsSpliced: a server-first session must be the kind
// plaintext routes were made to splice, both on an entrypoint that raced the
// backend against its silent client and on one that serves nothing but the
// tcp route. Nothing was read from the client in either, so the proxy must be
// given the socket itself: any wrapper would hide the *net.TCPConn, and every
// byte of the session would go back through a user-space buffer each way.
func TestAServerFirstSessionIsSpliced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(*testing.T, string) *runningEntrypoint
	}{
		{"raced on a mixed entrypoint", mixedEntrypoint},
		{"at once on a tcp-only entrypoint", tcpOnlyEntrypoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, stopBackend := serveBackend(t, greetThenEcho)
			t.Cleanup(stopBackend)
			e := tc.start(t, backend)
			before := l4.SplicedSessions()

			c := dialBounded(t, e.addr)
			if got, err := bufio.NewReader(c).ReadString('\n'); err != nil || got != serverFirstGreeting {
				t.Fatalf("a client waiting for the server read %q (%v), want the greeting %q", got, err, serverFirstGreeting)
			}
			// The greeting reaches the client through the session's copy,
			// which starts after the session is counted.
			if n := l4.SplicedSessions() - before; n != 1 {
				t.Errorf("%d sessions spliced with one server-first session open, want 1", n)
			}
			_ = c.Close()
			e.drained(t)
			if n := l4.SplicedSessions() - before; n != 0 {
				t.Errorf("%d sessions still counted as spliced after the only one ended", n)
			}
		})
	}
}
