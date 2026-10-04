// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/redact"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTheDebuggerCapturesNoMoreThanATraceKeeps: max_body_size is the
// operator's to set, and nothing bounded it, so a debugger set to 10 MiB held
// up to 20 MiB per in-flight request -- a request and a response body -- on a
// 2 GB host, to store a trace that keeps 64 KiB of each (ADR 0060). The
// capture is bounded by what is kept; the client and the backend still get
// every byte.
func TestTheDebuggerCapturesNoMoreThanATraceKeeps(t *testing.T) {
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Debugger: &gateonv1.DebuggerConfig{Enabled: true, MaxBodySize: 10 << 20},
	}}
	payload := strings.Repeat("a", 1<<20)
	var upstreamGot int
	h := Debugger(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		upstreamGot = int(n)
		_, _ = io.WriteString(w, payload)
	}))

	rs := &request.RequestState{}
	r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	r = r.WithContext(request.WithState(r.Context(), rs))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if upstreamGot != len(payload) || rec.Body.Len() != len(payload) {
		t.Fatalf("the backend read %d bytes and the client got %d, want %d each", upstreamGot, rec.Body.Len(), len(payload))
	}
	if rs.DebugInfo == nil {
		t.Fatal("the debugger captured nothing")
	}
	if got := len(rs.DebugInfo.RequestBody); got != redact.MaxBodyBytes {
		t.Errorf("captured a %d-byte request body, want %d", got, redact.MaxBodyBytes)
	}
	if got := len(rs.DebugInfo.ResponseBody); got != redact.MaxBodyBytes {
		t.Errorf("captured a %d-byte response body, want %d", got, redact.MaxBodyBytes)
	}
}
