// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSchemaValidationRefusesAmbiguousKeys: decoding into `any` kept the last
// of two colliding keys, so the schema validated one value while a backend
// whose parser keeps the first, or a Go backend matching a struct field
// case-insensitively, acted on the other.
func TestSchemaValidationRefusesAmbiguousKeys(t *testing.T) {
	h, reached := schemaMiddleware(t, SchemaValidationConfig{
		Schema: `{"type":"object","properties":{"role":{"enum":["user"]},` +
			`"profile":{"type":"object","properties":{"role":{"enum":["user"]}}}}}`,
	})
	bodies := map[string]string{
		"first-wins duplicate": `{"role":"admin","role":"user"}`,
		"case variant":         `{"role":"user","Role":"admin"}`,
		"nested duplicate":     `{"profile":{"role":"admin","role":"user"}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			before := *reached
			rec := postJSON(h, io.NopCloser(strings.NewReader(body)), int64(len(body)))
			if *reached != before || rec.Code != http.StatusBadRequest {
				t.Errorf("status %d, forwarded=%v; want refused with 400", rec.Code, *reached != before)
			}
		})
	}

	body := `{"role":"user","profile":{"role":"user"}}`
	if rec := postJSON(h, io.NopCloser(strings.NewReader(body)), int64(len(body))); rec.Code != http.StatusNoContent {
		t.Errorf("an unambiguous valid body got %d, want it forwarded", rec.Code)
	}
}
