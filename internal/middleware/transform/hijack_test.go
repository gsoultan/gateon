// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"testing"
)

// TestTransformResponseWriterPreservesHijacker is this package's half of
// TestResponseWriterWrappersPreserveHijacker in package middleware, which
// covers the wrappers that stayed there.
//
// The guard exists because a body-rewriting wrapper that forgets to forward
// Hijack silently breaks every WebSocket upgrade on every route it sits on --
// the cause of the "hijack failed" 500 on the Synology WebSocket route. Split
// rather than dropped: the type is unexported, and exporting a wrapper so a
// test in another package can name it would be a worse trade than two tests.
func TestTransformResponseWriterPreservesHijacker(t *testing.T) {
	var w http.ResponseWriter = &transformResponseWriter{}

	if _, ok := w.(http.Hijacker); !ok {
		t.Error("transformResponseWriter does not implement http.Hijacker; every " +
			"WebSocket upgrade on a route using BodyTransform fails with 500")
	}
}
