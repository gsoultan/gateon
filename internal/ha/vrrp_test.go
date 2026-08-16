// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import "testing"

// validVIP and validInterfaceName are the only thing standing between an
// API-settable config value and an argument passed to `ip` running as root.
// exec.Command runs no shell, so this is not command injection today — but that
// safety comes from *how* the command is invoked, and these tests exist so that
// tightening stays tight if the invocation ever changes. They were untested.

func TestValidVIP(t *testing.T) {
	valid := []string{
		"192.168.1.100",
		"192.168.1.100/24",
		"10.0.0.1/32",
		"0.0.0.0",
		"::1",
		"2001:db8::1",
		"2001:db8::/32",
		"fe80::1/64",
	}
	for _, s := range valid {
		if !validVIP(s) {
			t.Errorf("validVIP(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"example.com",            // a name is not an address; no DNS at this layer
		"192.168.1.256",          // out of range
		"192.168.1.100/33",       // impossible prefix
		"192.168.1.100 dev eth0", // extra argument smuggled into one value
		"192.168.1.100;reboot",   // shell metacharacter
		"192.168.1.100\nfoo",     // embedded newline
		"-192.168.1.100",         // reads as an option
		"--help",                 // reads as an option
		"$(id)",                  // substitution, were a shell ever involved
		"`id`",                   // ditto
		"192.168.1.100/24 extra", // trailing junk
		" 192.168.1.100",         // leading space
		"192.168.1.100 ",         // trailing space
	}
	for _, s := range invalid {
		if validVIP(s) {
			t.Errorf("validVIP(%q) = true, want false", s)
		}
	}
}

func TestValidInterfaceName(t *testing.T) {
	valid := []string{
		"eth0",
		"ens192",
		"br-lan",
		"eth0.100", // VLAN sub-interface
		"veth_a1",
		"eth0:1", // alias
		"a",
		"abcdefghijklmno", // exactly IFNAMSIZ-1 = 15
	}
	for _, s := range valid {
		if !validInterfaceName(s) {
			t.Errorf("validInterfaceName(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"abcdefghijklmnop", // 16, over the kernel limit
		"-eth0",            // leading dash reads as an option to `ip`
		"--help",           // ditto
		"eth0 dev br0",     // second argument smuggled in
		"eth0;reboot",      // shell metacharacter
		"eth0\nreboot",     // embedded newline
		"eth0/../br0",      // path traversal shape
		"$(id)",            // substitution
		"eth0`id`",         // ditto
		"eth0|cat",         // pipe
		"eth0&",            // background
		"eth 0",            // embedded space
		"eth\t0",           // embedded tab
		"eth0#",            // comment character
		"étho0",            // non-ASCII
	}
	for _, s := range invalid {
		if validInterfaceName(s) {
			t.Errorf("validInterfaceName(%q) = true, want false", s)
		}
	}
}

// The 15-character ceiling is IFNAMSIZ-1 and is a real kernel limit, not a
// stylistic one, so the boundary is pinned explicitly rather than left to the
// table above.
func TestValidInterfaceName_LengthBoundary(t *testing.T) {
	name := ""
	for i := range 16 {
		name += "a"
		want := i < 15
		if got := validInterfaceName(name); got != want {
			t.Fatalf("validInterfaceName(%d chars) = %v, want %v", len(name), got, want)
		}
	}
}
