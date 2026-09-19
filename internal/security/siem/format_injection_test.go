// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package siem

import (
	"strings"
	"testing"
	"time"
)

// TestSyslogFormatterNeutralisesLineBreaks is the regression test for a log
// injection into the SIEM. Over TCP a syslog record ends at the newline, and
// the threat pipeline puts the *decoded* request path into both the message
// and the request_uri field -- so a request for /.env%0a<134>1 ... tripped the
// honeypot and shipped two records: the real one, and one the attacker wrote.
// CEF already escaped line breaks; syslog appended the message raw and the
// SD-PARAM escaping covered only the three characters RFC 5424 names.
func TestSyslogFormatterNeutralisesLineBreaks(t *testing.T) {
	e := Event{
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Kind:     KindThreat,
		Name:     "honeypot_triggered",
		Severity: "high",
		SourceIP: "203.0.113.9",
		Message:  "Access to deception trap path: /.env\n<134>1 2026-01-02T03:04:05Z host1 Gateon - - - forged",
		Fields:   map[string]string{"request_uri": "/.env\r\nforged=1"},
	}

	out := string(syslogFormatter{version: "1.0", hostname: "host1"}.format(e))

	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("record carries %d line feeds, want only the terminator:\n%q", n, out)
	}
	if strings.Contains(out, "\r") {
		t.Fatalf("carriage return survived into the record: %q", out)
	}
	// The line breaks become the two-character sequences \r and \n, and RFC
	// 5424 then requires each backslash in a PARAM-VALUE to be doubled, so on
	// the wire the field reads /.env\\r\\nforged=1 and decodes back to the
	// visible escapes rather than to a record boundary.
	if !strings.Contains(out, `request_uri="/.env\\r\\nforged=1"`) {
		t.Fatalf("field value was not escaped in place: %q", out)
	}
}
