// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestFactoryRefusesToBuildOnThePlaceholder: a config can reach the factory
// without passing a store -- a middlewares.json written by hand, or seeded from
// an export, which carries placeholders by design. Built, the jwt middleware
// would accept any token HMAC-signed with "__gateon_redacted__", a key printed
// in the source; refused, the route serves the refusal it serves for any
// security middleware it cannot build.
func TestFactoryRefusesToBuildOnThePlaceholder(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, m := range []*gateonv1.Middleware{
		{Id: "jwt-1", Type: "auth", Config: map[string]string{"type": "jwt", "secret": "__gateon_redacted__"}},
		{Id: "hmac-1", Type: "hmac", Config: map[string]string{"secret": "__gateon_redacted__"}},
		{Id: "basic-1", Type: "auth", Config: map[string]string{"type": "basic", "users": "alice:__gateon_redacted__"}},
	} {
		_, err := f.Create(m, "route-1")
		if err == nil || !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("%s built on the placeholder (err %v); it must be refused", m.Id, err)
		}
	}
}
