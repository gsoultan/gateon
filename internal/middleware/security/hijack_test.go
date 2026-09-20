// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"testing"
)

// TestSecurityResponseWriterWrappersPreserveHijacker is this package's half of
// a guard ADR-0002 has now split twice. Every middleware that wraps
// http.ResponseWriter to inspect or rewrite a response body has to forward
// Hijack, because one that forgets silently breaks WebSocket upgrades on every
// route it sits on -- which is what caused the "hijack failed" 500 on the
// Synology WebSocket e2e route.
//
// The other halves are TestResponseWriterWrappersPreserveHijacker in
// internal/middleware/security/waf (wafResponseWriter) and
// TestTransformResponseWriterPreservesHijacker in internal/middleware/transform
// (transformResponseWriter). Splitting the table beat exporting three internal
// wrappers so one package could name them.
func TestSecurityResponseWriterWrappersPreserveHijacker(t *testing.T) {
	wrappers := map[string]http.ResponseWriter{
		"deceptionResponseWriter": &deceptionResponseWriter{},
		"breadcrumbWriter":        &breadcrumbWriter{},
	}

	for name, w := range wrappers {
		t.Run(name, func(t *testing.T) {
			if _, ok := w.(http.Hijacker); !ok {
				t.Errorf("%s does not implement http.Hijacker; every WebSocket "+
					"upgrade on a route using it fails with 500", name)
			}
		})
	}
}
