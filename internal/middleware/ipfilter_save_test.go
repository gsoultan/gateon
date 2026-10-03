// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSavingAnIPFilterWithAMalformedEntryIsRefused: Validate is what every
// transport's middleware save calls (the domain service's ConfigValidator is
// this factory), so a deny list it cannot read is refused at save, by name,
// rather than saved to block nothing.
func TestSavingAnIPFilterWithAMalformedEntryIsRefused(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	err := f.Validate(&gateonv1.Middleware{Id: "deny", Type: "ipfilter",
		Config: map[string]string{"deny_list": "198.51.100.4, 127.0.0.*"}})
	if err == nil || !strings.Contains(err.Error(), `"127.0.0.*"`) {
		t.Fatalf("err = %v, want the save refused naming 127.0.0.*", err)
	}
	if err := f.Validate(&gateonv1.Middleware{Id: "ok", Type: "ipfilter",
		Config: map[string]string{"deny_list": "127.0.0.0/24"}}); err != nil {
		t.Fatalf("a well-formed deny list was refused: %v", err)
	}
}
