// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"strings"
	"testing"
)

// TestAnalyzeLogsDoesNotCallRefusalsAndProbesHealthy is truth T41: the log
// assistant called two "POST /login 401" access lines and a "GET /.env" probe
// "No errors or warnings detected -- the gateway appears healthy", because
// it counted only the log level, and an access line is INFO whatever its
// status. It now reads the status and path an access line carries.
func TestAnalyzeLogsDoesNotCallRefusalsAndProbesHealthy(t *testing.T) {
	text := []string{
		`time=2026-10-04T10:00:00Z level=INFO msg="access log" host=a method=POST path=/login client=1.2.3.4 status=401 route=r`,
		`time=2026-10-04T10:00:01Z level=INFO msg="access log" host=a method=POST path=/login client=1.2.3.4 status=401 route=r`,
		`time=2026-10-04T10:00:02Z level=INFO msg="access log" host=a method=GET path=/.env client=1.2.3.4 status=404 route=r`,
	}
	json := []string{
		`{"time":"2026-10-04T10:00:00Z","level":"INFO","msg":"access log","method":"POST","path":"/login","status":401}`,
		`{"time":"2026-10-04T10:00:01Z","level":"INFO","msg":"access log","method":"POST","path":"/login","status":401}`,
		`{"time":"2026-10-04T10:00:02Z","level":"INFO","msg":"access log","method":"GET","path":"/.env","status":404}`,
	}
	for name, lines := range map[string][]string{"text": text, "json": json} {
		got := analyzeLogs(lines)
		if strings.Contains(got, "healthy") {
			t.Errorf("%s: refusals and a probe were called healthy: %q", name, got)
		}
		for _, want := range []string{"2 refused (401/403/429)", "1 probe for a sensitive path"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: analysis does not say %q: %q", name, want, got)
			}
		}
	}
	ok := []string{`time=2026-10-04T10:00:00Z level=INFO msg="access log" method=GET path=/index.html status=200`}
	if got := analyzeLogs(ok); !strings.Contains(got, "healthy") {
		t.Errorf("a served request is not reported healthy: %q", got)
	}
	five := []string{`time=2026-10-04T10:00:00Z level=INFO msg="access log" method=GET path=/api status=502`}
	if got := analyzeLogs(five); !strings.Contains(got, "1 server error (5xx)") {
		t.Errorf("a 502 is not reported as a server error: %q", got)
	}
}
