package httputil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteForbidden(t *testing.T) {
	tests := []struct {
		name            string
		accept          string
		reason          string
		wantContentType string
		wantBodyParts   []string
	}{
		{
			name:            "BrowserGetsAnimatedHTML",
			accept:          "text/html,application/xhtml+xml",
			reason:          "Forbidden",
			wantContentType: "text/html; charset=utf-8",
			wantBodyParts:   []string{"<!doctype html>", "Gateon", "403", "Forbidden"},
		},
		{
			name:            "APIClientGetsPlainText",
			accept:          "application/json",
			reason:          "Forbidden",
			wantContentType: "text/plain; charset=utf-8",
			wantBodyParts:   []string{"Forbidden"},
		},
		{
			name:            "ReasonIsHTMLEscaped",
			accept:          "text/html",
			reason:          "Forbidden: <script>",
			wantContentType: "text/html; charset=utf-8",
			wantBodyParts:   []string{"Forbidden: &lt;script&gt;"},
		},
		{
			name:            "EmptyReasonDefaults",
			accept:          "application/json",
			reason:          "",
			wantContentType: "text/plain; charset=utf-8",
			wantBodyParts:   []string{"Forbidden"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()

			WriteForbidden(rec, req, tc.reason)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d; want %d", rec.Code, http.StatusForbidden)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.wantContentType {
				t.Errorf("Content-Type = %q; want %q", ct, tc.wantContentType)
			}
			body := rec.Body.String()
			for _, part := range tc.wantBodyParts {
				if !strings.Contains(body, part) {
					t.Errorf("body missing %q; got %q", part, body)
				}
			}
			// The HTML branch must not leak the raw placeholder token.
			if strings.Contains(body, forbiddenReasonToken) {
				t.Errorf("body still contains placeholder token %q", forbiddenReasonToken)
			}
		})
	}
}
