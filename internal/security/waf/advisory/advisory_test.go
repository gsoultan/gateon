// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sampleOf is a sample of a request from client, as the request path builds it.
func sampleOf(t *testing.T, target, client string) *Sample {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = client + ":40000"
	r.Header.Set("User-Agent", "probe/1.0")
	r.Header.Set("Authorization", "Bearer the-clients-secret")
	r.Header.Set("Cookie", "session=the-clients-session")
	s, ok := Capture(r, "shop", WhySampled, nil)
	if !ok {
		t.Fatalf("no sample for %s", target)
	}
	return s
}

// running starts a queue against a worker and stops it with the test.
func running(t *testing.T, worker http.Handler, cfg Config) (*Queue, chan Finding) {
	t.Helper()
	srv := httptest.NewServer(worker)
	t.Cleanup(srv.Close)
	cfg.URL = srv.URL
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1
	}
	cfg.Backoff = time.Millisecond
	q, err := New(cfg)
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	findings := make(chan Finding, 16)
	q.SetSink(func(f Finding) { findings <- f })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return q, findings
}

func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// answering flags every sample it is sent and passes on what it was sent.
func answering(seen chan<- string, token *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if token != nil {
			token.Store(r.Header.Get("Authorization"))
		}
		var b Batch
		_ = json.Unmarshal(raw, &b)
		var a Answer
		for _, s := range b.Samples {
			a.Verdicts = append(a.Verdicts, Verdict{ID: s.ID, Label: "sqli", Score: 80, Reason: "looks like an injection"})
		}
		_ = json.NewEncoder(w).Encode(a)
		seen <- string(raw)
	}
}

// The worker is shown the request and never who sent it or what it was
// carrying for them; the verdict still finds its way back to the client.
func TestAVerdictComesBackForAClientTheWorkerWasNeverShown(t *testing.T) {
	seen := make(chan string, 4)
	var token atomic.Value
	q, findings := running(t, answering(seen, &token), Config{Capacity: 8, Token: "gateway-token"})

	if !q.Offer(sampleOf(t, "/items?id=7&api_key=the-clients-key", "203.0.113.9")) {
		t.Fatal("a queue with room refused a sample")
	}
	body := wait(t, seen, "the batch")
	for _, private := range []string{"203.0.113.9", "the-clients-secret", "the-clients-session", "the-clients-key", "40000"} {
		if strings.Contains(body, private) {
			t.Errorf("the worker was sent %q:\n%s", private, body)
		}
	}
	for _, want := range []string{`"target":"/items"`, `"id":"7"`, `"why":"sampled"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the batch lacks %s:\n%s", want, body)
		}
	}
	if got := token.Load(); got != "Bearer gateway-token" {
		t.Errorf("the worker was given %q as the gateway's credential", got)
	}

	f := wait(t, findings, "the verdict")
	if f.Sample.Source.Addr != "203.0.113.9" || f.Sample.Source.Route != "shop" {
		t.Errorf("the verdict came back for %+v", f.Sample.Source)
	}
	if strings.Contains(f.Sample.Source.URI, "the-clients-key") {
		t.Errorf("the kept URI carries a credential: %s", f.Sample.Source.URI)
	}
	if f.Verdict.Label != "sqli" || f.Verdict.Score != 80 || f.Mode != Record {
		t.Errorf("verdict %+v in mode %q", f.Verdict, f.Mode)
	}
	if st := q.Status(); st.Sent != 1 || st.Flagged != 1 || st.Failed != 0 || st.LastContact == 0 {
		t.Errorf("status %+v", st)
	}
}

// The request path is never made to wait: a full queue turns the sample away
// and says how many it has.
func TestAFullQueueDropsAndCounts(t *testing.T) {
	q, err := New(Config{URL: "https://worker.example", Capacity: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is sending, so the queue only fills.
	for i := range 5 {
		kept := q.Offer(sampleOf(t, "/a", "203.0.113.9"))
		if kept != (i < 2) {
			t.Errorf("offer %d kept=%v", i, kept)
		}
	}
	if q.Room() {
		t.Error("a full queue says it has room")
	}
	if st := q.Status(); st.Offered != 5 || st.Dropped != 3 || st.Queued != 2 || st.QueueCapacity != 2 {
		t.Errorf("status %+v", st)
	}
}

// With no worker there is nothing to offer to, and nothing runs.
func TestNoWorkerMeansNothingIsKeptOrSent(t *testing.T) {
	q, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if q.Enabled() || q.Room() || q.Due(1) || q.Offer(sampleOf(t, "/a", "203.0.113.9")) {
		t.Error("a queue with no worker took a sample")
	}
	q.Run(t.Context()) // returns at once
	if st := q.Status(); st.Configured || st.Offered != 0 {
		t.Errorf("status %+v", st)
	}
}

// A worker is another host. What it says is believed only about what it was
// asked, and only in the shape the Security Hub can show.
func TestAWorkersAnswerIsNotBelievedPastWhatItWasAsked(t *testing.T) {
	worker := func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		_ = json.NewDecoder(r.Body).Decode(&b)
		id := b.Samples[0].ID
		_ = json.NewEncoder(w).Encode(Answer{Verdicts: []Verdict{
			{ID: "99999", Label: "sqli", Score: 100, Reason: "a sample nobody sent"},
			{ID: id, Label: "<script>alert(1)</script>", Score: 5000, Reason: "line one\r\nline two\x00" + strings.Repeat("é", 400)},
			{ID: id, Label: "sqli", Score: 100, Reason: "the same sample again"},
		}})
	}
	q, findings := running(t, http.HandlerFunc(worker), Config{Capacity: 8, Mode: Reputation})
	q.Offer(sampleOf(t, "/a", "203.0.113.9"))

	f := wait(t, findings, "the verdict")
	if f.Verdict.Label != noLabel || f.Verdict.Score != 100 || f.Mode != Reputation {
		t.Errorf("verdict %+v in mode %q", f.Verdict, f.Mode)
	}
	if len(f.Verdict.Reason) > maxReason || strings.ContainsAny(f.Verdict.Reason, "\r\n\x00") ||
		!strings.HasPrefix(f.Verdict.Reason, "line one  line two") {
		t.Errorf("reason %q", f.Verdict.Reason)
	}
	if strings.ToValidUTF8(f.Verdict.Reason, "") != f.Verdict.Reason {
		t.Errorf("the reason was cut inside a character: %q", f.Verdict.Reason)
	}
	// A second sample's verdict means the first batch is finished with.
	q.Offer(sampleOf(t, "/b", "203.0.113.9"))
	wait(t, findings, "the second verdict")
	select {
	case extra := <-findings:
		t.Errorf("a sample was judged twice: %+v", extra.Verdict)
	default:
	}
	// Each batch had two verdicts that answer nothing: the sample nobody
	// sent, and the second word on one already judged.
	if st := q.Status(); st.Unmatched != 4 || st.Flagged != 2 {
		t.Errorf("status %+v", st)
	}
}

// A worker that is down costs the samples it was sent and nothing else, and
// is asked again once it answers.
func TestAFailingWorkerLosesItsBatchAndIsAskedAgain(t *testing.T) {
	var calls atomic.Int32
	seen := make(chan string, 4)
	ok := answering(seen, nil)
	worker := func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "down for maintenance at https://internal.example/?token=abc", http.StatusServiceUnavailable)
			return
		}
		ok(w, r)
	}
	q, findings := running(t, http.HandlerFunc(worker), Config{Capacity: 8})

	q.Offer(sampleOf(t, "/lost", "203.0.113.9"))
	q.Offer(sampleOf(t, "/kept", "203.0.113.9"))
	f := wait(t, findings, "the verdict after the worker came back")
	if f.Sample.Target != "/kept" {
		t.Errorf("the verdict is for %s", f.Sample.Target)
	}
	q.Offer(sampleOf(t, "/after", "203.0.113.9"))
	wait(t, findings, "the next verdict")
	st := q.Status()
	if st.Failed != 1 || st.Sent != 2 || st.LastError != "" {
		t.Errorf("status %+v", st)
	}
}

// What a failing worker says is not repeated to the dashboard: only that it
// answered, and with what status.
func TestAFailureIsReportedWithoutTheWorkersWords(t *testing.T) {
	asked := make(chan struct{}, 8)
	worker := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<b>secret</b>", http.StatusBadGateway)
		asked <- struct{}{}
	}
	q, _ := running(t, http.HandlerFunc(worker), Config{Capacity: 8})
	q.Offer(sampleOf(t, "/a", "203.0.113.9"))
	wait(t, asked, "the first batch")
	// A second batch is only asked after the first failure was recorded.
	q.Offer(sampleOf(t, "/b", "203.0.113.9"))
	wait(t, asked, "the second batch")
	if st := q.Status(); st.LastError != "the worker answered 502" || st.Failed < 1 {
		t.Errorf("status %+v", st)
	}
}

// A redirect would carry the token and the samples wherever it pointed.
func TestARedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(other.Close)
	asked := make(chan struct{}, 8)
	worker := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+Path, http.StatusTemporaryRedirect)
		asked <- struct{}{}
	}
	q, _ := running(t, http.HandlerFunc(worker), Config{Capacity: 8, Token: "gateway-token"})
	q.Offer(sampleOf(t, "/a", "203.0.113.9"))
	wait(t, asked, "the first batch")
	q.Offer(sampleOf(t, "/b", "203.0.113.9"))
	wait(t, asked, "the second batch")
	if elsewhere.Load() != 0 {
		t.Error("the batch followed a redirect")
	}
	if st := q.Status(); st.LastError != "the worker answered 307" {
		t.Errorf("status %+v", st)
	}
}

func TestAWorkerAddressMustBeTLSOrThisHost(t *testing.T) {
	for raw, usable := range map[string]bool{
		"https://worker.example":            true,
		"https://worker.example:8443/":      true,
		"http://127.0.0.1:8787":             true,
		"http://localhost:8787":             true,
		"http://[::1]:8787":                 true,
		"http://worker.example":             false,
		"http://10.0.0.5:8787":              false,
		"https://user:pass@worker.example":  false,
		"https://worker.example/?key=abc":   false,
		"ftp://worker.example":              false,
		"worker.example":                    false,
		"http://localhost.attacker.example": false,
	} {
		_, err := New(Config{URL: raw, Capacity: 1})
		if (err == nil) != usable {
			t.Errorf("%s: usable=%v, err=%v", raw, usable, err)
		}
	}
	if _, err := New(Config{URL: "https://worker.example", Mode: "block"}); err == nil {
		t.Error("a mode that does not exist was accepted")
	}
}

func TestDueOffersOneInRate(t *testing.T) {
	q, _ := New(Config{URL: "https://worker.example", Capacity: 1})
	n := 0
	for range 100 {
		if q.Due(10) {
			n++
		}
	}
	if n != 10 || q.Due(0) {
		t.Errorf("one in ten of a hundred is %d", n)
	}
}

func TestBackoffDoublesToAMinute(t *testing.T) {
	if got := backoffAfter(time.Second, 1); got != time.Second {
		t.Errorf("first failure waits %s", got)
	}
	if got := backoffAfter(time.Second, 4); got != 8*time.Second {
		t.Errorf("fourth failure waits %s", got)
	}
	if got := backoffAfter(time.Second, 500); got != maxBackoff {
		t.Errorf("the five-hundredth failure waits %s", got)
	}
}
