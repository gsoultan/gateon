// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestClamAVWithNoAddressRefusesTheBuild: with enable_clamav on and no
// address on the middleware or in the global config, the scan was skipped
// and every upload came back clean -- a route that read as virus-scanned
// scanned nothing. file_security is a security middleware, so refusing the
// build takes the route out of service with the key named, until there is a
// scanner to ask.
func TestClamAVWithNoAddressRefusesTheBuild(t *testing.T) {
	global := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	gc := global.Get(t.Context())
	gc.Waf.ClamavAddr = ""
	gc.Waf.Clamav.ClamavAddr = ""
	if err := global.Update(t.Context(), gc); err != nil {
		t.Fatal(err)
	}
	f := NewFactory(nil, global, nil, nil, t.TempDir())

	_, err := f.Create(&gateonv1.Middleware{Type: "file_security", Config: map[string]string{"enable_clamav": "true"}}, t.Name())
	if err == nil || !strings.Contains(err.Error(), "clamav_addr") {
		t.Fatalf("ClamAV on with no address anywhere: err = %v, want a config error naming clamav_addr", err)
	}

	for _, cfg := range []map[string]string{
		{"enable_clamav": "true", "clamav_addr": "tcp://127.0.0.1:3310"},
		{"enable_clamav": "false"},
	} {
		if _, err := f.Create(&gateonv1.Middleware{Type: "file_security", Config: cfg}, t.Name()); err != nil {
			t.Errorf("%v refused: %v", cfg, err)
		}
	}
}
