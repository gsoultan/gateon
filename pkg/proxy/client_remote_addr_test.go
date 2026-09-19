// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRewriteRequestKeepsResolvedClientIPForProxyProtocolTargets guards the
// request state shared with every middleware on the request. To get the peer's
// port to the PROXY-protocol dialer, rewriteRequest wrote r.RemoteAddr into
// RequestState.ClientRemoteAddr -- the field the entrypoint middleware had
// memoised the trust-resolved client IP in, and the field request.GetClientIP
// returns first. Everything that asked for the client IP after the proxy ran
// (WAF telemetry, tracing) then got "ip:port" for the rest of the request.
func TestRewriteRequestKeepsResolvedClientIPForProxyProtocolTargets(t *testing.T) {
	rs := &request.RequestState{ClientRemoteAddr: "198.51.100.7"} // what EntryPoint memoises
	in := httptest.NewRequest(http.MethodGet, "http://gateway.example/path", nil)
	in.RemoteAddr = "198.51.100.7:40000"
	in = in.WithContext(context.WithValue(in.Context(), request.RequestStateContextKey{}, rs))
	pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}

	state := newTargetStateWithProxy("http://backend:8080", 1, true,
		gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V1)
	(&ProxyHandler{}).rewriteRequest(pr, state)

	if rs.ClientRemoteAddr != "198.51.100.7" {
		t.Fatalf("rewriteRequest overwrote the memoised client IP: got %q, want %q", rs.ClientRemoteAddr, "198.51.100.7")
	}
	// The dialer must still see the peer with its port, or the PROXY header
	// would carry source port 0.
	if got := clientRemoteAddrFromContext(pr.Out.Context()); got != "198.51.100.7:40000" {
		t.Fatalf("PROXY header source = %q, want %q", got, "198.51.100.7:40000")
	}
	if got := pr.Out.Header.Get("X-Real-IP"); got != "198.51.100.7" {
		t.Fatalf("X-Real-IP = %q, want %q", got, "198.51.100.7")
	}
}
