// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// InjectsCredentialUpstream is what ADR 0038 keys the admin-only binding rule
// on: a middleware that delivers a credential to the route's backend. It must
// catch the request-header and query-parameter shapes and must not fire on the
// response direction, an empty value or a non-credential name.
func TestInjectsCredentialUpstream(t *testing.T) {
	inject := []struct {
		name string
		mw   *gateonv1.Middleware
	}{
		{"request Authorization header", &gateonv1.Middleware{
			Type: "headers", Config: map[string]string{"set_request_Authorization": "Bearer sk-live-123"},
		}},
		{"added request X-Api-Key", &gateonv1.Middleware{
			Type: "headers", Config: map[string]string{"add_request_X-Api-Key": "abc123"},
		}},
		{"rewrite credential query", &gateonv1.Middleware{
			Type: "rewrite", Config: map[string]string{"query_access_token": "t0ken"},
		}},
		{"mixed case type", &gateonv1.Middleware{
			Type: "Headers", Config: map[string]string{"set_request_Proxy-Authorization": "Basic x"},
		}},
	}
	for _, c := range inject {
		if !InjectsCredentialUpstream(c.mw) {
			t.Errorf("%s: InjectsCredentialUpstream = false, want true", c.name)
		}
	}

	benign := []struct {
		name string
		mw   *gateonv1.Middleware
	}{
		{"nil", nil},
		{"response credential header (goes to client)", &gateonv1.Middleware{
			Type: "headers", Config: map[string]string{"set_response_Authorization": "Bearer x"},
		}},
		{"empty value injects nothing", &gateonv1.Middleware{
			Type: "headers", Config: map[string]string{"set_request_Authorization": "  "},
		}},
		{"non-credential request header", &gateonv1.Middleware{
			Type: "headers", Config: map[string]string{"set_request_X-Trace-Id": "abc"},
		}},
		{"non-credential query", &gateonv1.Middleware{
			Type: "rewrite", Config: map[string]string{"query_page": "2"},
		}},
		{"unrelated type with a credential-looking scalar", &gateonv1.Middleware{
			Type: "auth", Config: map[string]string{"secret": "s3cr3t"},
		}},
	}
	for _, c := range benign {
		if InjectsCredentialUpstream(c.mw) {
			t.Errorf("%s: InjectsCredentialUpstream = true, want false", c.name)
		}
	}
}
