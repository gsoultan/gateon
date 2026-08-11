// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"crypto/tls"
	"testing"
)

// CodeQL's go/insecure-tls fires on these parsers because an operator can
// select TLS 1.0 or a suite from tls.InsecureCipherSuites(). That is
// deliberate — a gateway sometimes has to terminate for a client that cannot
// do better — and the defaults are safe: MinVersion falls back to TLS 1.2 and
// insecure suites are only reachable by naming one.
//
// What was missing is that taking the escape hatch was completely silent. The
// parsers now warn. These tests pin the behaviour the warnings describe, so
// that "insecure is allowed" cannot quietly become "insecure is the default".

func TestParseTLSVersionDefaultsAreSafe(t *testing.T) {
	tests := []struct {
		name string
		in   string
		def  uint16
		want uint16
	}{
		{name: "empty falls back to the caller's default", in: "", def: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "junk falls back rather than guessing", in: "not-a-version", def: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "TLS 1.2 by name", in: "TLS1.2", want: tls.VersionTLS12},
		{name: "TLS 1.3 by name", in: "TLS13", want: tls.VersionTLS13},
		// Allowed, and warned about — but it must still be exactly what was asked
		// for, not silently upgraded, or a legacy deployment breaks confusingly.
		{name: "TLS 1.0 is honoured when explicitly named", in: "TLS1.0", want: tls.VersionTLS10},
		{name: "TLS 1.1 is honoured when explicitly named", in: "TLS_1_1", want: tls.VersionTLS11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseTLSVersion(tt.in, tt.def); got != tt.want {
				t.Errorf("ParseTLSVersion(%q, %v) = %v, want %v", tt.in, tt.def, got, tt.want)
			}
		})
	}
}

// A weak suite must never arrive by accident — only by being named.
func TestParseCipherSuitesRequiresAnExplicitName(t *testing.T) {
	if got := ParseCipherSuites(nil); got != nil {
		t.Errorf("ParseCipherSuites(nil) = %v, want nil so Go's defaults apply", got)
	}
	if got := ParseCipherSuites([]string{}); got != nil {
		t.Errorf("ParseCipherSuites(empty) = %v, want nil", got)
	}

	// Names that match nothing must not silently become some other suite.
	if got := ParseCipherSuites([]string{"TLS_NOT_A_REAL_SUITE", "also-nonsense"}); got != nil {
		t.Errorf("ParseCipherSuites(unknown names) = %v, want nil rather than a guess", got)
	}
}

func TestParseCipherSuitesResolvesSecureNames(t *testing.T) {
	secure := tls.CipherSuites()
	if len(secure) == 0 {
		t.Skip("no secure suites reported by this Go build")
	}
	want := secure[0]

	// Both the full name and the TLS_-stripped short form must resolve.
	for _, in := range []string{want.Name, want.Name[len("TLS_"):]} {
		got := ParseCipherSuites([]string{in})
		if len(got) != 1 || got[0] != want.ID {
			t.Errorf("ParseCipherSuites(%q) = %v, want [%v]", in, got, want.ID)
		}
	}
}

// An insecure suite resolves when named — that is the escape hatch — but the
// caller gets exactly that suite and nothing extra.
func TestParseCipherSuitesHonoursNamedInsecureSuite(t *testing.T) {
	insecure := tls.InsecureCipherSuites()
	if len(insecure) == 0 {
		t.Skip("no insecure suites reported by this Go build")
	}
	want := insecure[0]

	got := ParseCipherSuites([]string{want.Name})
	if len(got) != 1 || got[0] != want.ID {
		t.Errorf("ParseCipherSuites(%q) = %v, want [%v]", want.Name, got, want.ID)
	}
}

// A mixed list keeps the good and drops the unusable, rather than failing shut
// on the whole list or passing the junk through.
func TestParseCipherSuitesMixedList(t *testing.T) {
	secure := tls.CipherSuites()
	if len(secure) == 0 {
		t.Skip("no secure suites reported by this Go build")
	}
	got := ParseCipherSuites([]string{secure[0].Name, "TLS_NOT_A_REAL_SUITE"})
	if len(got) != 1 || got[0] != secure[0].ID {
		t.Errorf("ParseCipherSuites(mixed) = %v, want just [%v]", got, secure[0].ID)
	}
}
