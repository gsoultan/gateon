package httputil

import (
	_ "embed"
	"html"
	"net/http"
	"strings"
)

//go:embed forbidden.html
var forbiddenPage string

const forbiddenReasonToken = "__REASON__"

// WriteForbidden writes a 403 Forbidden response. For browser clients (those that
// accept text/html) it serves a self-contained, animated HTML page featuring the
// Gateon logo. For API clients it falls back to a plain-text response so machine
// consumers keep receiving a simple, parseable body.
//
// reason is a short, human-readable explanation (e.g. "Forbidden",
// "Forbidden: Invalid Host"). It is HTML-escaped before rendering.
func WriteForbidden(w http.ResponseWriter, r *http.Request, reason string) {
	if reason == "" {
		reason = "Forbidden"
	}

	if !acceptsHTML(r) {
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	body := strings.Replace(forbiddenPage, forbiddenReasonToken, html.EscapeString(reason), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(body))
}

// acceptsHTML reports whether the request prefers an HTML response (i.e. a browser).
func acceptsHTML(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
