// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTheDebuggerFeedsTheTraceItsBodiesRedacted: the debugger stored what it
// captured on the request state, and the metrics middleware that records the
// trace looked for it only in the request's context -- where it is put only
// when there is no request state, which every request through an entrypoint
// has. So "Enable debugger" captured both bodies of every request and
// recorded neither; a trace never had a body. Fixed, the bodies reach the
// trace, and reach it without the password the client posted or the token the
// backend answered with (ADR 0060).
func TestTheDebuggerFeedsTheTraceItsBodiesRedacted(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Debugger: &gateonv1.DebuggerConfig{Enabled: true},
	}}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"access_token":"RESP-S3CRET","note":"visible-response"}`)
	})
	h := Metrics("debugger-route")(Debugger(store)(backend))

	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("user=visible-user&password=BODY-S3CRET"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(request.WithState(r.Context(), &request.RequestState{RequestID: request.GenerateID()}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	telemetry.FlushTraces()

	traces := telemetry.GetTracesFiltered(t.Context(), 10, false)
	if len(traces) != 1 {
		t.Fatalf("%d traces recorded, want 1", len(traces))
	}
	tr := traces[0]
	if tr.RequestBody != "user=visible-user&password=[REDACTED]" {
		t.Errorf("request body in the trace = %q", tr.RequestBody)
	}
	if tr.ResponseBody != `{"access_token":"[REDACTED]","note":"visible-response"}` {
		t.Errorf("response body in the trace = %q", tr.ResponseBody)
	}
}
