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
)

// rewriteRequest sets X-Real-IP and the X-Forwarded-* family from what the
// gateway observed, by their canonical spelling. A backend that folds
// header-name separators (PHP/CGI, WSGI, nginx) reads an underscore or dot
// alias as the same name, so a client-supplied X_Real_IP / X_Forwarded_For had
// to be stripped or it reached the backend as the gateway's value
// (CVE-2026-88879 class). The gateway-only X-Gateon-* headers are the same.
func TestRewriteRequestStripsGatewayHeaderAliases(t *testing.T) {
	rs := &request.RequestState{ClientRemoteAddr: "198.51.100.7"}
	in := httptest.NewRequest(http.MethodGet, "http://gateway.example/path", nil)
	in.RemoteAddr = "198.51.100.7:40000"
	in.Header.Set("X_Real_IP", "10.9.9.9")
	in.Header.Set("X_Forwarded_For", "10.9.9.9")
	in.Header.Set("X.Forwarded.Proto", "https")
	in.Header.Set("X_Gateon_Reputation", "100")
	in.Header.Set("X.Gateon.Ja4", "forged")
	in = in.WithContext(context.WithValue(in.Context(), request.RequestStateContextKey{}, rs))
	pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}

	(&ProxyHandler{}).rewriteRequest(pr, newTargetState("http://backend:8080", 1))

	for _, alias := range []string{
		"X_Real_IP", "X_Forwarded_For", "X.Forwarded.Proto",
		"X_Gateon_Reputation", "X.Gateon.Ja4",
	} {
		if vals := pr.Out.Header.Values(alias); len(vals) != 0 {
			t.Errorf("backend saw gateway-header alias %s = %q; it must be stripped", alias, vals)
		}
	}
	// The canonical values the gateway sets must be the real ones.
	if got := pr.Out.Header.Get("X-Real-IP"); got != "198.51.100.7" {
		t.Errorf("X-Real-IP = %q, want the gateway's %q", got, "198.51.100.7")
	}
	if got := pr.Out.Header.Get("X-Forwarded-For"); got != "198.51.100.7" {
		t.Errorf("X-Forwarded-For = %q, want the gateway's %q", got, "198.51.100.7")
	}
}
