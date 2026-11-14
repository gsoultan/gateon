// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import "testing"

// TestARouteCannotSendUploadsToARemoteScanner: a route's file_security
// middleware could name its own clamd, and whoever may write a middleware
// could name one elsewhere: every upload on that route was then sent, whole,
// to a host of their choosing, which also answered "clean". The scanner a
// route may name is one on the gateway itself; a remote one is the
// administrator's global setting.
func TestARouteCannotSendUploadsToARemoteScanner(t *testing.T) {
	for _, bad := range []string{
		"tcp://10.0.0.5:3310", "tcp://evil.example:3310", "tcp://127.0.0.1.evil.example:3310",
		"tcp://0.0.0.0:3310", "http://127.0.0.1:3310", "10.0.0.5:3310", "tcp://",
	} {
		if err := CheckFileSecuritySave(map[string]string{"clamav_addr": bad}); err == nil {
			t.Errorf("scanner %q saved on a route", bad)
		}
	}
	for _, ok := range []string{
		"", "tcp://127.0.0.1:3310", "tcp://localhost:3310", "tcp://[::1]:3310", "unix:///run/clamav/clamd.ctl",
	} {
		if err := CheckFileSecuritySave(map[string]string{"clamav_addr": ok}); err != nil {
			t.Errorf("scanner %q refused: %v", ok, err)
		}
	}
}
