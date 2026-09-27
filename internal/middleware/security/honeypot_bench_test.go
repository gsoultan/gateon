// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/request"
)

// BenchmarkHoneypotGlobal measures the global honeypot on an ordinary request.
//
// Every HTTP entrypoint carries it (entrypoint_http.go), so its ban check is paid
// by every request the gateway serves, trap or not. Keying an IPv6 ban on the
// /64 puts an address parse on that path for IPv6 clients, and this is the number
// that says what that costs. The IPv4 cases are the control: they are meant not
// to move.
//
// "quiet" is a gateway with no ban in force; "under-scan" has two thousand other
// clients banned, which is a busy public gateway on an ordinary day and the case
// where the ban check cannot be skipped.
//
// The request is built once, with the resolved client address on its state the
// way the entrypoint leaves it, so the loop measures the middleware rather than
// httptest parsing a request.
func BenchmarkHoneypotGlobal(b *testing.B) {
	globals := config.NewGlobalRegistry(filepath.Join(b.TempDir(), "global.json"))
	h := HoneypotGlobal(globals)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, state := range []string{"quiet", "under-scan"} {
		for _, tc := range []struct{ name, ip string }{
			{"ipv4", "203.0.113.42"},
			{"ipv6", "2001:db8:1:2:a:b:c:d"},
		} {
			b.Run(state+"/"+tc.name, func(b *testing.B) {
				benchHoneypotBans(b, state == "under-scan")
				req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
				req.RemoteAddr = "[" + tc.ip + "]:51234"
				req = req.WithContext(request.WithState(req.Context(),
					&request.RequestState{ClientRemoteAddr: tc.ip}))
				w := httptest.NewRecorder()

				b.ReportAllocs()
				for b.Loop() {
					h.ServeHTTP(w, req)
				}
			})
		}
	}
}

// benchHoneypotBans empties the ban list or fills it with a thousand IPv4 and a
// thousand IPv6 bans on other clients, and empties it again afterwards.
func benchHoneypotBans(b *testing.B, fill bool) {
	b.Helper()
	blocklistMu.Lock()
	clear(honeypotBlocklist)
	blocklistMu.Unlock()
	b.Cleanup(func() {
		blocklistMu.Lock()
		clear(honeypotBlocklist)
		blocklistMu.Unlock()
	})
	if !fill {
		return
	}
	until := time.Now().Add(time.Hour)
	for i := range 1000 {
		blockHoneypotIP(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1), until)
		blockHoneypotIP(fmt.Sprintf("2001:db8:ff:%x::1", i), until)
	}
}
