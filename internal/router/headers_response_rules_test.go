// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The headers middleware's response rules exist to change what the backend
// sends: del_response_X-Powered-By and del_response_Server hide the
// backend's software and version, and set_response_ replaces a value the
// backend chose -- the shipped "secure-api" preset sets Referrer-Policy and
// X-Frame-Options this way.
//
// They were applied to the response header map before the request went
// upstream, when it held nothing of the backend's. The reverse proxy then Adds
// every backend header to that map, so a deleted header came back, and a
// "set" value was joined by the backend's own as a second one. Referrer-Policy
// takes the last valid token, which was the backend's.
func TestHeadersMiddlewareResponseRulesApplyToBackendHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/5.4.0")
		w.Header().Set("Server", "Apache/2.2.14 (Ubuntu)")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	mwStore := fakeMWStore{m: map[string]*gateonv1.Middleware{
		"hdr": {Id: "hdr", Type: "headers", Config: map[string]string{
			"del_response_X-Powered-By":    "",
			"del_response_Server":          "",
			"set_response_Referrer-Policy": "strict-origin-when-cross-origin",
		}},
	}}
	rt := &gateonv1.Route{Id: "r-hdr", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http",
		Middlewares: []string{"hdr"}}
	addr := newRouteGateway(t, backend.URL, rt, mwStore, fakeGlobalStore{cfg: &gateonv1.GlobalConfig{}})

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET through the gateway: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	for _, name := range []string{"X-Powered-By", "Server"} {
		if v := resp.Header.Values(name); len(v) != 0 {
			t.Errorf("%s = %q reached the client; del_response_%s did not remove the backend's header",
				name, v, name)
		}
	}
	if got, want := resp.Header.Values("Referrer-Policy"), []string{"strict-origin-when-cross-origin"}; !slices.Equal(got, want) {
		t.Errorf("Referrer-Policy = %q, want exactly %q: set_response_ did not replace the backend's value",
			got, want)
	}
}
