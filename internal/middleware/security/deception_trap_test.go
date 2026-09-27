// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveThroughDeception runs one request through the deception middleware in
// front of a backend that answers with a small HTML page, and reports the
// response and whether the backend was reached.
func serveThroughDeception(t *testing.T, cfg DeceptionConfig, r *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><p>hello</p></body></html>")
	})
	rec := httptest.NewRecorder()
	Deception(cfg)(backend).ServeHTTP(rec, r)
	return rec, reached
}

// TestEveryDeceptionArtefactIsATrap: each artefact the middleware plants must
// catch whoever touches it. The hidden honey form was injected into every
// page with its path as the form's action, but that path was never checked,
// so a bot that found the form and submitted it went straight through to the
// backend -- the one trap the middleware sets whose bait it actually serves.
func TestEveryDeceptionArtefactIsATrap(t *testing.T) {
	cfg := DeceptionConfig{
		HoneypotPaths:        []string{"/.env"},
		InjectInvisibleLinks: true,
		InvisibleLinkPaths:   []string{"/old-admin"},
		HoneyForms:           []string{"/account/recover"},
		CanaryHeader:         "X-Debug-Token",
		CanaryToken:          "c4n4ry",
	}
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"honeypot path", httptest.NewRequest(http.MethodGet, "/.env", nil)},
		{"below a honeypot path", httptest.NewRequest(http.MethodGet, "/.env/backup", nil)},
		{"invisible link", httptest.NewRequest(http.MethodGet, "/old-admin", nil)},
		{"honey form submitted", httptest.NewRequest(http.MethodPost, "/account/recover",
			strings.NewReader("admin_password=hunter2"))},
		{"canary header replayed", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Debug-Token", "c4n4ry")
			return r
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, reached := serveThroughDeception(t, cfg, tc.req)
			if reached || rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: status %d, backend reached = %v; want 403 and the backend untouched",
					tc.req.Method, tc.req.URL.Path, rec.Code, reached)
			}
		})
	}

	rec, reached := serveThroughDeception(t, cfg, httptest.NewRequest(http.MethodGet, "/account", nil))
	if !reached || rec.Code != http.StatusOK {
		t.Errorf("an ordinary page: status %d, backend reached = %v; want 200 from the backend", rec.Code, reached)
	}
}

// TestDeceptionMarkupEscapesConfiguredPaths: the trap paths are written into
// every proxied HTML page. Written raw, a quote in one ends the attribute, and
// whoever can edit a middleware can put script into every site behind it.
func TestDeceptionMarkupEscapesConfiguredPaths(t *testing.T) {
	cfg := DeceptionConfig{
		InjectInvisibleLinks: true,
		InvisibleLinkPaths:   []string{`/a"><script>alert(1)</script>`},
		HoneyForms:           []string{`/f" onmouseover="alert(2)`},
	}
	rec, _ := serveThroughDeception(t, cfg, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	for _, raw := range []string{"<script>alert(1)</script>", `" onmouseover="alert(2)`} {
		if strings.Contains(body, raw) {
			t.Errorf("configured path reached the page unescaped: %q in %s", raw, body)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the escaped link is missing from the page: %s", body)
	}
}

// TestInvisibleLinksAskCrawlersNotToFollow: search engines read markup, not
// styles, so a hidden link is followed by a crawler as readily as by a bot --
// and a crawler that trips the trap is recorded as a critical threat and
// refused. nofollow is the signal well-behaved crawlers honour; bots ignore it.
func TestInvisibleLinksAskCrawlersNotToFollow(t *testing.T) {
	cfg := DeceptionConfig{InjectInvisibleLinks: true, InvisibleLinkPaths: []string{"/old-admin"}}
	rec, _ := serveThroughDeception(t, cfg, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := rec.Body.String(); !strings.Contains(body, `href="/old-admin" rel="nofollow"`) {
		t.Errorf("injected link does not carry rel=\"nofollow\": %s", body)
	}
}
