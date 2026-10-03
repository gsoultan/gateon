// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mgmtorigin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func browserRequest(method, target string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestAllows(t *testing.T) {
	p := New([]string{"https://Dash.Example", "*", "https://bad.example/path", "not a url"})
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		want bool
	}{
		{"not a browser", nil, true},
		{"same origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://gw.example:8080"}, true},
		{"typed into the address bar", map[string]string{"Sec-Fetch-Site": "none"}, true},
		{"same site", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://gw.example:9090"}, false},
		{"cross site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, false},
		{"cross site, trusted", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://dash.example"}, true},
		{"cross site, no Origin", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"older browser, own host", map[string]string{"Origin": "http://GW.example:8080"}, true},
		{"older browser, other port", map[string]string{"Origin": "http://gw.example:9090"}, false},
		{"older browser, opaque", map[string]string{"Origin": "null"}, false},
		{"older browser, trusted", map[string]string{"Origin": "https://dash.example"}, true},
		{"wildcard is not trust", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "*"}, false},
		{"an origin with a path is not trusted", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://bad.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := browserRequest(http.MethodPost, "http://gw.example:8080/v1/global", tc.hdr)
			if got := p.Allows(r); got != tc.want {
				t.Errorf("Allows = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestANilPolicyTrustsOnlyTheManagementOrigin(t *testing.T) {
	var p *Policy
	if !p.Allows(browserRequest(http.MethodPost, "http://gw.example/", map[string]string{"Origin": "http://gw.example"})) {
		t.Error("a nil policy refused the management origin")
	}
	if p.Allows(browserRequest(http.MethodPost, "http://gw.example/", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://x.example"})) {
		t.Error("a nil policy allowed a cross-site request")
	}
}

func TestGuard(t *testing.T) {
	reached := false
	h := New(nil).Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	crossSite := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
	for _, tc := range []struct {
		name, method, path, body string
		hdr                      map[string]string
		want                     int
	}{
		{"cross-site read passes", http.MethodGet, "/v1/global", "", crossSite, http.StatusOK},
		{"cross-site write refused", http.MethodDelete, "/v1/routes/x", "", crossSite, http.StatusForbidden},
		{"cross-site websocket refused", http.MethodGet, "/v1/logs", "",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", "Upgrade": "websocket"}, http.StatusForbidden},
		{"JSON write passes", http.MethodPut, "/v1/routes", "{}", map[string]string{"Content-Type": "application/json; charset=utf-8"}, http.StatusOK},
		{"Connect write passes", http.MethodPost, "/gateon.v1.ApiService/X", "{}", map[string]string{"Content-Type": "application/connect+json"}, http.StatusOK},
		{"gRPC-Web write passes", http.MethodPost, "/gateon.v1.ApiService/X", "x", map[string]string{"Content-Type": "application/grpc-web+proto"}, http.StatusOK},
		{"text/plain write refused", http.MethodPost, "/v1/global", "{}", map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{"multipart upload passes", http.MethodPost, "/v1/certs/upload", "x", map[string]string{"Content-Type": "multipart/form-data; boundary=b"}, http.StatusOK},
		{"multipart elsewhere refused", http.MethodPost, "/v1/global", "x", map[string]string{"Content-Type": "multipart/form-data; boundary=b"}, http.StatusUnsupportedMediaType},
		{"bodiless write passes", http.MethodPost, "/v1/logout", "", nil, http.StatusOK},
		{"untyped body refused", http.MethodPost, "/v1/global", "{}", nil, http.StatusUnsupportedMediaType},
		{"a write outside the API is not typed", http.MethodPost, "/somewhere", "x", map[string]string{"Content-Type": "text/plain"}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			r := httptest.NewRequest(tc.method, "http://gw.example"+tc.path, strings.NewReader(tc.body))
			for k, v := range tc.hdr {
				r.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", rr.Code, tc.want, rr.Body.String())
			}
			if reached != (tc.want == http.StatusOK) {
				t.Errorf("handler reached = %v with status %d", reached, rr.Code)
			}
			if tc.want != http.StatusOK && rr.Header().Get("Cache-Control") != "no-store" {
				t.Error("a refusal was sent without Cache-Control: no-store")
			}
		})
	}
}
