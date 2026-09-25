// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestMalformedBooleanSettingsRefuseTheBuild gives every boolean setting a
// factory reads a value that is not a boolean. Each used to read as its
// default -- or, for bot management, as off unless it was the literal "true",
// and for forward auth as false unless "true", "1" or "yes" -- so a typo in
// fail_open, tls_insecure_skip_verify or a bot-management switch ran the
// gateway on a value nobody chose while the dashboard showed what was typed.
func TestMalformedBooleanSettingsRefuseTheBuild(t *testing.T) {
	cases := []struct {
		typ  string
		base map[string]string
		keys []string
	}{
		{"forwardedheaders", nil, []string{"trust_forward_header"}},
		{"deception", nil, []string{"inject_invisible_links", "enable_troll_response"}},
		{"grpcweb", nil, []string{"allow_credentials"}},
		{"file_security", nil, []string{"enable_clamav", "fail_open", "enable_signature_scan"}},
		{"ratelimit", nil, []string{"per_tenant"}},
		{"inflightreq", map[string]string{"amount": "10"}, []string{"per_ip"}},
		{"cors", nil, []string{"allow_credentials"}},
		{"headers", map[string]string{"sts_seconds": "3600"}, []string{"force_sts_header", "sts_include_subdomains", "sts_preload"}},
		{"bot_management", nil, []string{"enabled", "enable_js_challenge", "enable_browser_integrity"}},
		{"forwardauth", map[string]string{"address": "http://auth.internal"},
			[]string{"trust_forward_header", "forward_body", "preserve_request_method", "tls_insecure_skip_verify"}},
	}
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	for _, tc := range cases {
		for _, key := range tc.keys {
			t.Run(tc.typ+"/"+key, func(t *testing.T) {
				cfg := maps.Clone(tc.base)
				if cfg == nil {
					cfg = map[string]string{}
				}
				cfg[key] = "maybe"
				_, err := f.Create(&gateonv1.Middleware{Id: "m", Type: tc.typ, Config: cfg}, "r")
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("%s with %s=maybe: err = %v, want an error naming %s", tc.typ, key, err, key)
				}
			})
		}
	}
}

// TestBotManagementReadsEveryBooleanSpelling switches the JS challenge on with
// "True" and "1", which bot management read as off: only the literal "true"
// counted.
func TestBotManagementReadsEveryBooleanSpelling(t *testing.T) {
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{Id: "bot", Type: "bot_management", Config: map[string]string{
		"enabled": "True", "enable_js_challenge": "1", "secret_key": "k",
	}}, "r")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reached := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if reached {
		t.Fatal(`bot management configured with enabled="True", enable_js_challenge="1" let a client through unchallenged`)
	}
}

// TestForwardAuthRefusesAMalformedBodySize: the parse error was discarded and
// the 1 MiB default used instead.
func TestForwardAuthRefusesAMalformedBodySize(t *testing.T) {
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	for _, v := range []string{"10MB", "-1"} {
		_, err := f.Create(&gateonv1.Middleware{Id: "fa", Type: "forwardauth", Config: map[string]string{
			"address": "http://auth.internal", "max_body_size": v,
		}}, "r")
		if err == nil || !strings.Contains(err.Error(), "max_body_size") {
			t.Errorf("max_body_size=%q: err = %v, want an error naming max_body_size", v, err)
		}
	}
}
