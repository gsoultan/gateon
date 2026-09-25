// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The gateway's own error answers are JSON, say so, and carry nosniff
// themselves: since the entrypoint stopped applying a header preset to every
// response it serves, nothing else puts it there, and an error body a browser
// may sniff is one it may render. The request ID the response already carries
// is echoed so a user can quote it.
func TestWriteJSONErrorIsLabelledJSONAndNotSniffable(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "req-7")
	WriteJSONError(rec, http.StatusTooManyRequests, "too many requests", "rate_limited")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v: %q", err, rec.Body.String())
	}
	want := ErrorBody{Error: "too many requests", Message: "too many requests", Code: "rate_limited", RequestID: "req-7"}
	if body != want {
		t.Errorf("body = %+v, want %+v", body, want)
	}
}
