// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// schema_validation read the body up to the gateway's 10 MiB request limit and
// decoded all of it into `any`. Decoding JSON into `any` holds 6 to 45 times
// the input's length, so one 10 MiB array held about 225 MiB live, and nothing
// bounded how many such decodes ran at once. Root cause: the middleware
// trusted the request limit, which bounds bytes on the wire, to bound the
// cost of the decode, which is a multiple of them.

// countingBody counts how many bytes the middleware read from the client.
type countingBody struct {
	r    io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

// jsonArray is a JSON array of ones at least n bytes long.
func jsonArray(n int) string {
	return "[" + strings.Repeat("1,", n/2) + "1]"
}

func schemaMiddleware(t *testing.T, cfg SchemaValidationConfig) (http.Handler, *int) {
	t.Helper()
	if cfg.Schema == "" {
		cfg.Schema = `{"type":"array","items":{"type":"integer"}}`
	}
	mw, err := SchemaValidation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	})), &reached
}

func postJSON(h http.Handler, body io.ReadCloser, contentLength int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/items", body)
	req.ContentLength = contentLength
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAnOversizeSchemaBodyIsRefusedWithoutBeingDecoded(t *testing.T) {
	h, reached := schemaMiddleware(t, SchemaValidationConfig{MaxBodyBytes: 1 << 20})
	body := jsonArray(4 << 20)

	for _, declared := range []int64{int64(len(body)), -1} {
		cb := &countingBody{r: strings.NewReader(body)}
		rec := postJSON(h, cb, declared)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("a %d-byte body (declared %d) against a 1 MiB bound got %d; want 413",
				len(body), declared, rec.Code)
		}
		if cb.read > 1<<20+1 {
			t.Errorf("the middleware read %d bytes of a body it refuses; want at most the bound plus one", cb.read)
		}
	}
	if *reached != 0 {
		t.Errorf("an oversize body reached the origin unvalidated")
	}
}

func TestALargeButAllowedSchemaBodyIsStillValidated(t *testing.T) {
	h, reached := schemaMiddleware(t, SchemaValidationConfig{MaxBodyBytes: 1 << 20})

	valid := jsonArray(512 << 10)
	if rec := postJSON(h, io.NopCloser(strings.NewReader(valid)), int64(len(valid))); rec.Code != http.StatusNoContent {
		t.Fatalf("a valid 512 KiB body got %d; want it validated and passed", rec.Code)
	}
	invalid := strings.Replace(valid, "1,", `"x",`, 1)
	if rec := postJSON(h, io.NopCloser(strings.NewReader(invalid)), int64(len(invalid))); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid 512 KiB body got %d; want 400", rec.Code)
	}
	if *reached != 1 {
		t.Fatalf("the origin was reached %d times; want once, by the valid body", *reached)
	}
}

func TestALargeSchemaBodyWithNoDecodeSlotIsShed(t *testing.T) {
	withSchemaDecodeSlots(t, "1")
	h, reached := schemaMiddleware(t, SchemaValidationConfig{MaxBodyBytes: 1 << 20})

	// The one slot is taken, as by a decode still running.
	release, ok := schemaDecodes.acquire(t.Context())
	if !ok {
		t.Fatal("could not take the only slot")
	}

	large := jsonArray(128 << 10)
	post := func(body string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/items", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(large); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("a large body with every decode slot taken got %d (Retry-After %q); want 503 with Retry-After",
			rec.Code, rec.Header().Get("Retry-After"))
	}
	if *reached != 0 {
		t.Fatal("the origin saw a large body nobody validated")
	}
	// A small body never needs a slot.
	if rec := post("[1,2,3]"); rec.Code != http.StatusNoContent {
		t.Errorf("a small body got %d while the decode slots were full; want 204", rec.Code)
	}
	release()
	if rec := post(large); rec.Code != http.StatusNoContent {
		t.Errorf("a large body with a free slot got %d; want 204", rec.Code)
	}
}
