// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"io"
	"log/slog"
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

// TestAnalyzeLogsReadsFieldsNotTheTextAClientWrote: the tally used to search
// the whole line for " error " and for the first " status=", and the access
// log writes the client's path before its status. A probe for "/ error x"
// counted as an error, and a 503 to "/ status=200" read as a served request,
// so whoever sent the traffic chose what the Log Assistant said about it.
// The lines here are what slog itself writes, quoting and escaping included.
func TestAnalyzeLogsReadsFieldsNotTheTextAClientWrote(t *testing.T) {
	for name, newHandler := range map[string]func(io.Writer) slog.Handler{
		"text": func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		"json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		line := func(path string, status int) string {
			var b strings.Builder
			slog.New(newHandler(&b)).Info("access log", "method", "GET", "path", path, "status", status)
			return strings.TrimSpace(b.String())
		}
		got := analyzeLogs([]string{line("/ error x", 200)})
		if !strings.Contains(got, "0 error") || !strings.Contains(got, "healthy") {
			t.Errorf("%s: a served request whose path says error was counted as one: %q", name, got)
		}
		got = analyzeLogs([]string{line(`/ status=200 "status":200,`, 503)})
		if !strings.Contains(got, "1 server error (5xx)") {
			t.Errorf("%s: a 503 whose path names another status was not reported: %q", name, got)
		}
	}
}
