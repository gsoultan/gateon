// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// The recognition middlewares skip loopback -- the gateway's own calls -- and
// they asked who the client was with Cloudflare trust forced on, whatever the
// operator had configured. A request that reached them without the entrypoint
// having resolved its client, from an address in Cloudflare's published
// ranges, could name 127.0.0.1 in CF-Connecting-IP and be waved through
// unscanned. Every listener runs the entrypoint today, which is why this was
// latent; the scan must not depend on that.
func TestRecognitionIsNotSkippedByNamingLoopbackInAForwardingHeader(t *testing.T) {
	h := SQLiRecognition("r")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rs := &request.RequestState{}
	req := httptest.NewRequest(http.MethodGet, "/items?id=1'+OR+'1'='1", nil)
	req.RemoteAddr = "173.245.48.1:40000" // a Cloudflare edge address
	req.Header.Set(request.HeaderCloudflareConnectingIP, "127.0.0.1")
	req = req.WithContext(request.WithState(req.Context(), rs))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !rs.ExecutedSQLI {
		t.Fatal("a request naming loopback in CF-Connecting-IP skipped SQLi recognition; " +
			"with no Cloudflare trust configured the client is the peer, 173.245.48.1")
	}
}
