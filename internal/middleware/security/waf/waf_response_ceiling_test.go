// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gwaf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ceilingLimit is the response limit these tests run under: small, so a body
// of a few kilobytes is "larger than the limit" without a megabyte per test.
const (
	ceilingLimit = 1024
	ceilingTail  = "TAILMARK"
)

// ceilingWAF builds a blocking, response-inspecting WAF on route whose
// response limit is ceilingLimit, over an origin that streams body (no
// Content-Length) in 500-byte writes, gzipped when compress is set.
func ceilingWAF(t *testing.T, route string, body []byte, compress bool) http.Handler {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatal(err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP: true, EnableResponseInspection: true, DLPAction: dlpBlock, ParanoiaLevel: 2,
		WafRules: store, RouteID: route, ResponseBodyLimit: ceilingLimit, RequestBodyLimit: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if compress {
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		_, _ = zw.Write(body)
		_ = zw.Close()
		body = out.Bytes()
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if compress {
			w.Header().Set("Content-Encoding", "gzip")
		}
		for rest := body; len(rest) > 0; {
			n := min(500, len(rest))
			_, _ = w.Write(rest[:n])
			rest = rest[n:]
		}
	}))
}

// ceilingBody is about 12 KB of JSON rows that compress poorly (hex digests),
// with a row holding leak as card number starting at the first row boundary
// at or after byte offset at, and ceilingTail at the end.
func ceilingBody(leak string, at int) []byte {
	var b strings.Builder
	b.WriteString(`{"rows":[`)
	placed := false
	seed := []byte("ceiling")
	for b.Len() < 12<<10 {
		if !placed && b.Len() >= at {
			b.WriteString(`{"card":"` + leak + `"},`)
			placed = true
		}
		sum := sha256.Sum256(seed)
		seed = sum[:]
		b.WriteString(`{"sha":"` + hex.EncodeToString(seed) + `"},`)
	}
	b.WriteString(`{"end":"` + ceilingTail + `"}]}`)
	return []byte(b.String())
}

// ceilingResult is what a client read from a ceiling test's server.
type ceilingResult struct {
	status  int
	length  int64
	body    string
	readErr error
}

func fetchCeiling(t *testing.T, h http.Handler, acceptEncoding string) ceilingResult {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/export", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", acceptEncoding)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, readErr := io.ReadAll(resp.Body)
	return ceilingResult{resp.StatusCode, resp.ContentLength, string(got), readErr}
}

// wafFailures sums gateon_request_failures_total over route's WAF reasons:
// what the gateway claims it refused there.
func wafFailures(t *testing.T, route string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		telemetry.RequestFailuresTotal.Collect(ch)
		close(ch)
	}()
	var total float64
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["route"] == route && strings.HasPrefix(labels["reason"], "waf:") {
			total += pb.GetCounter().GetValue()
		}
	}
	return total
}

// TestDLPBlockPastTheLimitRefusesBeforeAnyByteLeaves is review 3's F1. At the
// response limit the held prefix was flushed undecided, the rest streamed, and
// the body phase ran only once everything had gone: a card in the first bytes
// of a response larger than the limit reached the client whole, under a 200,
// while the gateway recorded a block. The prefix is now decided before it
// leaves, so a finding in it is a complete 403.
func TestDLPBlockPastTheLimitRefusesBeforeAnyByteLeaves(t *testing.T) {
	for _, tc := range []struct {
		name     string
		at       int
		compress bool
	}{
		{"card at offset 0", 0, false},
		{"card mid-prefix", 500, false},
		{"card at offset 0, gzip", 0, true},
		{"card mid-prefix, gzip", 400, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := "test-ceiling-refuse-" + strings.ReplaceAll(tc.name, " ", "-")
			got := fetchCeiling(t, ceilingWAF(t, route, ceilingBody(leakVisa, tc.at), tc.compress), "gzip")
			if got.status != http.StatusForbidden || got.readErr != nil {
				t.Fatalf("status %d, read error %v, %d bytes; want a complete 403", got.status, got.readErr, len(got.body))
			}
			if got.body != string(responseBlockedBody) || got.length != int64(len(got.body)) {
				t.Errorf("refusal body %q under Content-Length %d", got.body, got.length)
			}
		})
	}
}

// TestBytesPastTheLimitAreUninspectedNotBlocked pins the other half of F1.
// Past the limit nothing is inspected (ADR 0062): the engine analyses a body
// it holds whole, so a finding there cannot stop bytes already sent. The
// response is delivered and counted as uninspected -- and not recorded as a
// block, which the gateway used to claim after forwarding every byte.
func TestBytesPastTheLimitAreUninspectedNotBlocked(t *testing.T) {
	for _, compress := range []bool{false, true} {
		name := map[bool]string{false: "identity", true: "gzip"}[compress]
		t.Run(name, func(t *testing.T) {
			route := "test-ceiling-past-" + name
			uninspected := uninspectedCount(t, route, reasonCeilingReached)
			failures := wafFailures(t, route)

			got := fetchCeiling(t, ceilingWAF(t, route, ceilingBody(leakVisa, 5000), compress), "gzip")
			if got.status != http.StatusOK || got.readErr != nil {
				t.Fatalf("status %d, read error %v; want the response delivered", got.status, got.readErr)
			}
			body := got.body
			if compress {
				body = gunzipString(t, body)
			}
			if !strings.HasSuffix(body, ceilingTail+`"}]}`) || !strings.Contains(body, leakVisa) {
				t.Errorf("the response was not delivered whole (%d bytes)", len(body))
			}
			if n := uninspectedCount(t, route, reasonCeilingReached); n != uninspected+1 {
				t.Errorf("uninspected responses went from %v to %v, want one more", uninspected, n)
			}
			if n := wafFailures(t, route); n != failures {
				t.Errorf("the WAF recorded %v refusals of a response it delivered", n-failures)
			}
		})
	}
}

func gunzipString(t *testing.T, s string) string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// TestUninspectedBodyIsDecidedBeforeItsHeaders covers the response whose body
// the engine is never given (a type no data-leak rule reads). Its body phase
// still runs -- a rule there may read the response headers -- and it used to
// run in finish, after the headers and the whole body had gone: the client got
// the 200 while the gateway recorded a block. With no body to wait for, it now
// runs before the header is committed, so a refusal is a complete 403.
func TestUninspectedBodyIsDecidedBeforeItsHeaders(t *testing.T) {
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatal(err)
	}
	store := waf.NewStore(d)
	if err := store.AddRule(t.Context(), &waf.Rule{
		ID: "1000077", Name: "Refuse a debug dump",
		Definition: `{"phase":"response_body","targets":["resp_headers:X-Debug-Dump"],
			"operator":{"kind":"equals","pattern":"on"},
			"severity":"critical","confidence":"certain",
			"msg":"Debug dump in a response","status":403}`,
		Format: waf.FormatGateon, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	mw, err := WAF(WAFConfig{EnableResponseInspection: true, WafRules: store, RouteID: "test-skip-body-decided"})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Debug-Dump", "on")
		_, _ = w.Write([]byte("\x89PNG not really"))
	}))

	got := fetchCeiling(t, h, "identity")
	if got.status != http.StatusForbidden || got.readErr != nil || got.body != string(responseBlockedBody) {
		t.Errorf("status %d, read error %v, body %q; want a complete 403", got.status, got.readErr, got.body)
	}
}

// TestRefusalAfterTheHeadersAbortsAndSaysSo covers a refusal reached once the
// headers have left. No decision is made that late any more, so it is
// defence in depth: should one be, the response cannot be refused, so it is
// cut -- recorded as aborted, not as a clean block, later writes fail so the
// origin copy stops, and the handler is aborted so the client sees a reset
// rather than a short body that reads as complete.
func TestRefusalAfterTheHeadersAbortsAndSaysSo(t *testing.T) {
	var outcomes []string
	w := &wafResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		headerWritten:  true,
		flushed:        true,
		onDecision:     func(_ gwaf.Decision, outcome string) { outcomes = append(outcomes, outcome) },
	}
	w.block(gwaf.Decision{})

	if len(outcomes) != 1 || outcomes[0] != kind.ActionAborted {
		t.Errorf("recorded %v, want exactly [%s]", outcomes, kind.ActionAborted)
	}
	if n, err := w.Write([]byte("more")); err == nil || n != 0 {
		t.Errorf("a write after the cut returned (%d, %v), want an error", n, err)
	}
	if msg := (wafObservation{outcome: kind.ActionAborted}).blockMessage(); strings.Contains(msg, "blocked") {
		t.Errorf("a cut response is logged as %q", msg)
	}
	defer func() {
		if p := recover(); p != http.ErrAbortHandler { //nolint:errorlint // the sentinel panic value itself
			t.Errorf("abortIfCut panicked with %v, want http.ErrAbortHandler", p)
		}
	}()
	w.abortIfCut()
}
