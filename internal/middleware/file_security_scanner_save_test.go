// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSavingARouteScannerElsewhereIsRefused: Validate is the one save path
// REST, gRPC and config import share, so the refusal of a remote scanner on a
// route's file_security middleware is proven here and not only on the
// function that decides it.
func TestSavingARouteScannerElsewhereIsRefused(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	save := func(addr string) error {
		return f.Validate(&gateonv1.Middleware{Id: "fs", Type: "file_security",
			Config: map[string]string{"enable_clamav": "true", "clamav_addr": addr}})
	}
	if err := save("tcp://10.0.0.5:3310"); err == nil {
		t.Error("a route's scanner on another host was saved")
	}
	if err := save("tcp://127.0.0.1:3310"); err != nil {
		t.Errorf("a route's scanner on the gateway was refused: %v", err)
	}
}
