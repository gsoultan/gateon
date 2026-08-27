// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package httputil

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestWriteHeaderCapturesStatus(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	sw.WriteHeader(http.StatusTeapot)

	if sw.Status != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", sw.Status, http.StatusTeapot)
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("underlying recorder got %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// TestWriteWithoutWriteHeaderRecords200 pins the case net/http documents: the
// first Write implies WriteHeader(200). Leaving Status at zero means every
// handler that writes a body without setting a status is reported as status 0 --
// internal/middleware/otel.go puts that straight into a span attribute, and two
// places in standard.go carry a `if statusCode == 0 { statusCode = 200 }` patch
// precisely because the writer did not do it.
func TestWriteWithoutWriteHeaderRecords200(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	if _, err := sw.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if sw.Status != http.StatusOK {
		t.Errorf("Status = %d after a bare Write, want %d; "+
			"the client received 200 but observability recorded %d",
			sw.Status, http.StatusOK, sw.Status)
	}
}

// TestExplicitStatusSurvivesLaterWrites guards the obvious way to get the above
// wrong: clamping on every Write would overwrite a real status with 200.
func TestExplicitStatusSurvivesLaterWrites(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	sw.WriteHeader(http.StatusNotFound)
	if _, err := sw.Write([]byte("nope")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if sw.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want %d; a later Write must not rewrite the status",
			sw.Status, http.StatusNotFound)
	}
}

func TestBytesWrittenAccumulates(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	for _, s := range []string{"one", "two", "three"} {
		if _, err := sw.Write([]byte(s)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if want := int64(len("onetwothree")); sw.BytesWritten != want {
		t.Errorf("BytesWritten = %d, want %d", sw.BytesWritten, want)
	}
}

func TestTTFBIsZeroUntilSomethingIsWritten(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	defer PutStatusResponseWriter(sw)

	if got := sw.TTFB(); got != 0 {
		t.Errorf("TTFB = %v before any write, want 0", got)
	}
	if sw.StatusRecorded() {
		t.Error("StatusRecorded() is true before any write")
	}

	sw.WriteHeader(http.StatusOK)

	if !sw.StatusRecorded() {
		t.Error("StatusRecorded() is false after WriteHeader")
	}
	if got := sw.TTFB(); got < 0 {
		t.Errorf("TTFB = %v, want a non-negative duration", got)
	}
}

// TestPooledWriterCarriesNothingBetweenRequests is the one that matters for a
// gateway: Country is per-request geo data, and a pooled writer that kept it
// would attribute one client's country to the next client's request.
func TestPooledWriterCarriesNothingBetweenRequests(t *testing.T) {
	t.Parallel()

	first := GetStatusResponseWriter(httptest.NewRecorder())
	first.WriteHeader(http.StatusInternalServerError)
	if _, err := first.Write([]byte("leaky")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first.Country = "AQ"
	PutStatusResponseWriter(first)

	// Not guaranteed to be the same object, but if it is, it must be clean.
	second := GetStatusResponseWriter(httptest.NewRecorder())
	defer PutStatusResponseWriter(second)

	if second.Status != 0 {
		t.Errorf("Status = %d on a fresh writer, want 0", second.Status)
	}
	if second.BytesWritten != 0 {
		t.Errorf("BytesWritten = %d on a fresh writer, want 0", second.BytesWritten)
	}
	if second.Country != "" {
		t.Errorf("Country = %q on a fresh writer; geo data leaked across requests",
			second.Country)
	}
	if second.StatusRecorded() {
		t.Error("StatusRecorded() is true on a fresh writer")
	}
	if got := second.TTFB(); got != 0 {
		t.Errorf("TTFB = %v on a fresh writer, want 0", got)
	}
}

func TestPutClearsTheUnderlyingWriter(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	sw := GetStatusResponseWriter(rec)
	PutStatusResponseWriter(sw)

	if sw.ResponseWriter != nil {
		t.Error("PutStatusResponseWriter left the response writer attached, " +
			"which pins the request's memory for as long as the pool holds it")
	}
}

func TestStatusString(t *testing.T) {
	t.Parallel()

	for _, code := range []int{0, 99, 100, 200, 404, 599, 600, 1000, -1} {
		if got, want := StatusString(code), strconv.Itoa(code); got != want {
			t.Errorf("StatusString(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestStatusStringDoesNotAllocateInRange(t *testing.T) {
	// No t.Parallel: AllocsPerRun panics if the test is running in parallel.

	// The cache exists to keep the hot path allocation-free; if it stops doing
	// that the reason to have it is gone.
	if n := testing.AllocsPerRun(100, func() { _ = StatusString(200) }); n != 0 {
		t.Errorf("StatusString(200) allocates %v times per run, want 0", n)
	}
}

// notAFlusher deliberately implements only http.ResponseWriter.
type notAFlusher struct{ http.ResponseWriter }

func TestOptionalInterfacesDegrade(t *testing.T) {
	t.Parallel()

	sw := GetStatusResponseWriter(notAFlusher{httptest.NewRecorder()})
	defer PutStatusResponseWriter(sw)

	// Flush on a non-flusher must be a no-op rather than a panic: the WAF and
	// SSE paths call it unconditionally.
	sw.Flush()

	if _, _, err := sw.Hijack(); err != http.ErrNotSupported {
		t.Errorf("Hijack error = %v, want %v", err, http.ErrNotSupported)
	}
	if err := sw.Push("/x", nil); err != http.ErrNotSupported {
		t.Errorf("Push error = %v, want %v", err, http.ErrNotSupported)
	}
}

type recordingFlusher struct {
	http.ResponseWriter
	flushed  bool
	hijacked bool
	pushed   string
}

func (r *recordingFlusher) Flush() { r.flushed = true }
func (r *recordingFlusher) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	return nil, nil, nil
}
func (r *recordingFlusher) Push(target string, _ *http.PushOptions) error {
	r.pushed = target
	return nil
}

func TestOptionalInterfacesPassThrough(t *testing.T) {
	t.Parallel()

	inner := &recordingFlusher{ResponseWriter: httptest.NewRecorder()}
	sw := GetStatusResponseWriter(inner)
	defer PutStatusResponseWriter(sw)

	sw.Flush()
	if !inner.flushed {
		t.Error("Flush did not reach the underlying writer")
	}
	if _, _, err := sw.Hijack(); err != nil {
		t.Errorf("Hijack: %v", err)
	}
	if !inner.hijacked {
		t.Error("Hijack did not reach the underlying writer")
	}
	if err := sw.Push("/asset.js", nil); err != nil {
		t.Errorf("Push: %v", err)
	}
	if inner.pushed != "/asset.js" {
		t.Errorf("Push target = %q, want %q", inner.pushed, "/asset.js")
	}
}
