// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/server/readiness"
)

// TestReadyzNamesAnEntrypointThatDidNotBind: /readyz looked at the telemetry
// store and nothing else, so a gateway with an entrypoint that never bound
// answered ready. It answers 503 and names the entrypoint and its address.
func TestReadyzNamesAnEntrypointThatDidNotBind(t *testing.T) {
	readiness.ListenerFailed("readyz-websecure", "127.0.0.1:1", errors.New("bind: address already in use"))
	t.Cleanup(func() { readiness.ListenerBound("readyz-websecure", "127.0.0.1:1") })

	mux := http.NewServeMux()
	registerGlobalHandlers(mux, signInAPI{}, &Deps{})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d with an entrypoint that did not bind, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "readyz-websecure") {
		t.Errorf("/readyz does not name the entrypoint: %s", rr.Body.String())
	}
}
