// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingBody struct {
	data []byte
	pos  int
}

func (f *failingBody) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, errors.New("connection reset by peer")
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

func (f *failingBody) Close() error { return nil }

// TestTransformRequestBodyRestoresBytesItConsumedOnReadError covers the third
// of four sites where a body peek dropped what it had already taken off the
// client's stream. transformRequestBody returned bare on a read error and the
// caller forwards the request regardless, so the upstream got a body with a
// hole at the front and nothing to indicate it.
func TestTransformRequestBodyRestoresBytesItConsumedOnReadError(t *testing.T) {
	const prefix = "TRANSFORM-BODY-PREFIX-THAT-MUST-SURVIVE"

	r := httptest.NewRequest(http.MethodPost, "http://example.com/u", nil)
	r.Body = &failingBody{data: []byte(prefix)}

	transformRequestBody(r, BodyTransformConfig{RequestSearch: "x", RequestReplace: "y"})

	got, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(got), prefix) {
		t.Errorf("upstream would receive %q, missing the %d bytes consumed "+
			"before the read failed", string(got), len(prefix))
	}
}
