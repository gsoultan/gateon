// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bufio"
	"bytes"
	"html"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// DeceptionConfig defines configuration for Deception middleware.
type DeceptionConfig struct {
	HoneypotPaths        []string
	InjectInvisibleLinks bool
	InvisibleLinkPaths   []string
	HoneyForms           []string // Injected hidden forms
	RouteID              string
	EnableTrollResponse  bool
	CanaryHeader         string // attractive-looking header name
	CanaryToken          string // attractive-looking header value
}

// Deception middleware provides path honeypots, invisible link injection, and canary tokens.
// trollReputationThreshold is the score below which a client that trips a trap
// gets the troll response rather than a plain 403. A client the gateway still
// rates well is more likely a browser replaying a cached link than an attacker
// probing, and deserves an ordinary error.
const trollReputationThreshold = 50

func Deception(cfg DeceptionConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveDeception(cfg, next, w, r)
		})
	}
}

func serveDeception(cfg DeceptionConfig, next http.Handler, w http.ResponseWriter, r *http.Request) {
	if threatType, details, tripped := cfg.trapFor(r); tripped {
		cfg.refuse(w, r, threatType, details)
		return
	}

	// Inject Canary Header into response
	if cfg.CanaryHeader != "" && cfg.CanaryToken != "" {
		w.Header().Set(cfg.CanaryHeader, cfg.CanaryToken)
	}

	if (!cfg.InjectInvisibleLinks || len(cfg.InvisibleLinkPaths) == 0) && len(cfg.HoneyForms) == 0 {
		next.ServeHTTP(w, r)
		return
	}

	// Wrap response to inject tokens if it's HTML
	next.ServeHTTP(&deceptionResponseWriter{ResponseWriter: w, cfg: cfg}, r)
}

// trapFor reports which deception artefact this request touched. Each of the
// three is something no legitimate client has a reason to reach: a canary
// header the gateway itself planted and only an attacker would replay, a path
// that exists solely to be trapped, and a link rendered invisible so only
// something reading the markup would follow it.
func (cfg DeceptionConfig) trapFor(r *http.Request) (threatType, details string, tripped bool) {
	if cfg.CanaryHeader != "" && cfg.CanaryToken != "" &&
		r.Header.Get(cfg.CanaryHeader) == cfg.CanaryToken {
		return "canary_token_reused",
			"Attacker reused injected canary header: " + cfg.CanaryHeader, true
	}

	path := r.URL.Path
	for _, trap := range cfg.HoneypotPaths {
		if trap != "" && (path == trap || strings.HasPrefix(path, trap+"/")) {
			return "honeypot_triggered", "Access to trap path: " + trap, true
		}
	}

	for _, link := range cfg.InvisibleLinkPaths {
		if link != "" && path == link {
			return "deception_link_triggered",
				"Access to invisible deception link: " + link, true
		}
	}

	// The hidden forms post here. The form was injected into every page and
	// its action was never checked, so a bot that found the bait and took it
	// went straight through to the backend.
	for _, form := range cfg.HoneyForms {
		if form != "" && path == form {
			return "deception_form_triggered", "Submission to hidden deception form: " + form, true
		}
	}

	return "", "", false
}

// refuse records the trap that fired and answers the request. The severity is
// kind's, not an upper-case literal: every consumer of a threat record --
// severityRank, the SIEM mapping, the dashboard's critical-or-high tile --
// compares lower-case, so "CRITICAL" ranked below "low" and was counted by
// nothing. Same bug the reputation blocker had.
func (cfg DeceptionConfig) refuse(w http.ResponseWriter, r *http.Request, threatType, details string) {
	kind.RecordThreat(r, kind.Threat{
		Type:        threatType,
		Score:       100,
		Details:     details,
		RouteID:     cfg.RouteID,
		Category:    "deception",
		Severity:    kind.SeverityCritical,
		ActionTaken: kind.ActionBlocked,
	})

	if cfg.EnableTrollResponse &&
		telemetry.GetReputationScore(telemetry.GetReputationID(r)) < trollReputationThreshold {
		serveTrollResponse(w)
		return
	}

	http.Error(w, "Forbidden", http.StatusForbidden)
}

type deceptionResponseWriter struct {
	http.ResponseWriter
	cfg         DeceptionConfig
	wroteHeader bool
	injected    bool
}

// rewritable reports whether this response's body may be edited: HTML, and
// not content-encoded, since a trap link spliced into gzip bytes corrupts the
// stream rather than hiding in the page.
func (w *deceptionResponseWriter) rewritable() bool {
	h := w.Header()
	return strings.Contains(h.Get("Content-Type"), "text/html") && h.Get("Content-Encoding") == ""
}

// WriteHeader drops Content-Length from any response whose body may grow.
// It used to do so for 200 only, while Write injects whatever the status, so
// an HTML error page overran the length it had declared.
func (w *deceptionResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	if w.rewritable() {
		w.Header().Del("Content-Length")
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying writer so a WebSocket upgrade behind the
// deception middleware can take the raw connection. Breadcrumb injection only
// applies to an HTML response body, which a hijacked connection does not have.

// Flush forwards to the underlying writer so a Server-Sent Events stream behind
// this middleware reaches the client as it is produced.
//
// Embedding http.ResponseWriter promotes only Header, Write and WriteHeader, so
// a wrapper silently stops being an http.Flusher -- and an SSE response then
// buffers until the upstream closes, arriving complete and far too late. That
// reads as a dead feed rather than as a middleware bug, which is why it
// survived: Hijack was added here for WebSocket upgrades and Flush was not,
// so the streaming case that fails is the one nobody was thinking about.
func (w *deceptionResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *deceptionResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

// Write splices the trap links and forms in before the page's closing body
// tag, once.
//
// It reports len(b) written, not the length of the enlarged buffer. io.Writer
// requires n <= len(p), and httputil.ReverseProxy reads anything else as
// io.ErrShortWrite and aborts the handler -- which is what this did to every
// proxied HTML page, the client seeing a dropped connection.
func (w *deceptionResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.injected || !w.rewritable() {
		return w.ResponseWriter.Write(b)
	}
	idx := bytes.LastIndex(b, []byte("</body>"))
	if idx == -1 {
		return w.ResponseWriter.Write(b)
	}
	w.injected = true
	return writeAround(w.ResponseWriter, b, idx, w.cfg.markup())
}

// markup is the hidden links and forms spliced into a page.
//
// The paths are escaped: they were written raw, so a quote in one ended the
// attribute and whoever could edit a middleware could put script into every
// site behind it. Links carry rel="nofollow" because crawlers read markup, not
// styles -- a search engine follows a hidden link as readily as a bot does,
// and one that trips the trap is refused as a critical threat. Well-behaved
// crawlers honour nofollow; the bots the trap is for do not.
func (cfg DeceptionConfig) markup() string {
	var sb strings.Builder
	for _, link := range cfg.InvisibleLinkPaths {
		sb.WriteString(`<a href="`)
		sb.WriteString(html.EscapeString(link))
		sb.WriteString(`" rel="nofollow" style="display:none" aria-hidden="true" tabIndex="-1"></a>`)
	}
	for _, form := range cfg.HoneyForms {
		sb.WriteString(`<form action="`)
		sb.WriteString(html.EscapeString(form))
		sb.WriteString(`" method="POST" style="display:none" aria-hidden="true"><input type="text" name="admin_password"></form>`)
	}
	return sb.String()
}

// writeAround writes b to dst with insert in front of b[idx:], and reports
// how much of b it wrote, as io.Writer requires.
//
// The page goes out in place, around the markup, rather than spliced into a
// new buffer: that was a copy of the proxy's chunk, up to 32 KiB, on every
// HTML response an injecting writer touched.
func writeAround(dst io.Writer, b []byte, idx int, insert string) (int, error) {
	n, err := dst.Write(b[:idx])
	if err != nil {
		return n, err
	}
	if _, err := io.WriteString(dst, insert); err != nil {
		return n, err
	}
	m, err := dst.Write(b[idx:])
	return n + m, err
}
