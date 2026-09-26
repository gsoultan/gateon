// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DiscoverGrpcServices used to guard against SSRF by comparing the raw host
// string to "localhost", "127.0.0.1" and "::1". That let an operator point it
// at 169.254.169.254 (the cloud instance-metadata service), any loopback
// address other than 127.0.0.1, the unspecified address, or a hostname
// resolving to any of them. It now enforces the same policy the tech probe does
// (discovery.BlockedProbeTarget), so these targets are refused before a socket
// is opened. Hermetic: each is a literal IP, rejected by the pre-dial check
// with no outbound connection.
func TestDiscoverGrpcServicesRefusesSSRFTargets(t *testing.T) {
	// Force the loopback opt-in off so the loopback case is deterministic
	// regardless of the ambient environment.
	t.Setenv("GATEON_ALLOW_LOOPBACK_PROBE", "0")
	s := &ApiService{}
	cases := []struct{ name, url string }{
		{"cloud metadata link-local", "h2c://169.254.169.254:443"},
		{"loopback beyond 127.0.0.1", "h2c://127.0.0.2:50051"},
		{"unspecified address", "h2c://0.0.0.0:50051"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err := s.DiscoverGrpcServices(ctx, &gateonv1.DiscoverGrpcServicesRequest{Url: tc.url})
			if err == nil {
				t.Fatalf("%s: expected an SSRF refusal, got nil error", tc.url)
			}
			if !strings.Contains(err.Error(), "refusing to probe") {
				t.Fatalf("%s: error = %q; want a refusal, the target reached the dialer instead", tc.url, err)
			}
		})
	}
}
