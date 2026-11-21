// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// openUntilRefused opens streams on one QUIC connection to an HTTP/3
// entrypoint, without sending anything on them, until the server's stream
// limit refuses one, and returns how many it opened. It stops at max.
func openUntilRefused(t *testing.T, open func() error, max int) int {
	t.Helper()
	for n := range max {
		err := open()
		var limit *quic.StreamLimitReachedError
		if errors.As(err, &limit) {
			return n
		}
		if err != nil {
			t.Fatalf("stream %d: %v", n+1, err)
		}
	}
	return max
}

func dialH3Entrypoint(t *testing.T) *quic.Conn {
	t.Helper()
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	deps.BaseHandler = http.HandlerFunc(slowHandler)
	ep := &gateonv1.EntryPoint{Id: "h3-streams", Address: freeTCPAndUDPAddr(t), Type: gateonv1.EntryPoint_HTTP3,
		Tls: &gateonv1.TlsConfig{Enabled: true}}
	addr := httpEntrypointFor(t, ep, deps)
	tlsConf := clientTLS.Clone()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

// One QUIC connection could hold 1000 request streams on every profile, so
// 256 connections from one address held 256,000: the HTTP/2 stream flood of
// review D2, moved to UDP (audit 2026-11-20 A2). The cap is now the
// profile's, as HTTP/2's is.
func TestAnHTTP3ConnectionHoldsNoMoreStreamsThanItsCap(t *testing.T) {
	t.Setenv("GATEON_H3_MAX_CONCURRENT_STREAMS", "7")
	conn := dialH3Entrypoint(t)
	if got := openUntilRefused(t, func() error { _, err := conn.OpenStream(); return err }, 1000); got != 7 {
		t.Fatalf("opened %d request streams on one connection, want the cap of 7", got)
	}
	// Control and the two QPACK streams are all a client needs; 500 were allowed.
	if got := openUntilRefused(t, func() error { _, err := conn.OpenUniStream(); return err }, 500); got != quicMaxIncomingUniStreams {
		t.Fatalf("opened %d unidirectional streams, want %d", got, quicMaxIncomingUniStreams)
	}
}

func TestTheHTTP3StreamCapIsTheProfilesHTTP2One(t *testing.T) {
	for _, tier := range []config.Tier{config.TierMinimal, config.TierStandard, config.TierEnterprise} {
		t.Run(string(tier), func(t *testing.T) {
			t.Setenv("GATEON_PROFILE", string(tier))
			if got, want := h3MaxConcurrentStreams(), int64(h2MaxConcurrentStreams()); got != want {
				t.Fatalf("HTTP/3 streams per connection = %d, want HTTP/2's %d", got, want)
			}
		})
	}
	t.Setenv("GATEON_H3_MAX_CONCURRENT_STREAMS", "42")
	if got := h3MaxConcurrentStreams(); got != 42 {
		t.Fatalf("with the override set, cap = %d, want 42", got)
	}
}
