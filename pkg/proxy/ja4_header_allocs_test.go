// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// Every proxied request removes the client's X-Gateon-JA4 and sets the
// gateway's. The name was spelled with "JA4" in capitals, which is not how
// net/http stores a header, so each Del and each Set built the canonical
// spelling again: an allocation per request on the proxy's hot path, and the
// +1 that benchstat showed against main when the Del was added. Setting it
// now costs only the value's slice.
func TestSettingTheGatewayJA4HeaderAllocatesOnlyItsValue(t *testing.T) {
	out := make(http.Header, 8)
	in := httptest.NewRequest(http.MethodGet, "/", nil)
	in = in.WithContext(request.WithState(in.Context(), &request.RequestState{JA4H: "ge11nn0100_494aa2c544e1"}))

	if n := testing.AllocsPerRun(200, func() { setGatewayJA4(out, in) }); n > 1 {
		t.Fatalf("setting the gateway's JA4 header allocated %v times per request; its value's slice is the only one it needs", n)
	}
	if got := out.Values("X-Gateon-JA4"); len(got) != 1 || got[0] != "ge11nn0100_494aa2c544e1" {
		t.Fatalf("header is %q", got)
	}
}
