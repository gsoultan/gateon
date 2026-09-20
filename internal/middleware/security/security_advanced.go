// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/entropy"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/security/scanner"
	"github.com/gsoultan/gateon/internal/telemetry"
)

var xssScanner = scanner.NewScanner([]string{
	"<script", "javascript:", "onload=", "onerror=", "eval(", "atob(",
	"alert(", "prompt(", "confirm(", "<img", "<svg", "onerror",
	"document.cookie", "window.location",
})

var sqliScanner = scanner.NewScanner([]string{
	"union select", "select * from", "insert into", "update ", "delete from",
	"drop table", "truncate table", "information_schema", "--", "/*", "*/",
	" ' or 1=1", " \" or 1=1", "sleep(", "benchmark(", "pg_sleep(", "waitfor delay",
})

var genericAttackScanner = scanner.NewScanner([]string{
	"__proto__", "constructor.prototype", "constructor[prototype]",
	"() { :; }", "() { :;};", // Shellshock
	"${jndi:",                                                     // Log4Shell
	"class.module.classLoader",                                    // Spring4Shell
	"; cat /etc/passwd", "; id", "; whoami", "; curl ", "; wget ", // Shell Injection
	"coinhive.min.js", "authedmine.min.js", "cryptonight.wasm", // Malicious scripts
	"String.fromCharCode", "unescape(", "%u00", "eval(atob(", "navigator.sendBeacon", "new WebSocket(", "document.write(", "document.createElement('script')", // Malicious JS
})

var gamblingScanner = scanner.NewScanner([]string{
	"betting", "gambling", "casino", "slot machine", "poker", "sportsbook", "jackpot", "lottery", "bookmaker", "odds payout", "wagering", "baccarat", "blackjack", "roulette",
})

var phpScanner = scanner.NewScanner([]string{
	"<?php", "file_get_contents(", "include(", "require(", "eval(", "exec(", "system(", "passthru(", "shell_exec(", "base64_decode(", "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE", "$_FILES",
})

var fileUploadScanner = scanner.NewScanner([]string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".asp", ".aspx", ".jsp", ".jspx", ".sh", ".py", ".pl", ".exe", ".cgi", ".htaccess",
})

// Tarpit middleware introduces progressive delays for suspicious clients based on fingerprint reputation.
func Tarpit(baseDelay, maxDelay time.Duration, scoreThreshold float64) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// IsLoopback was being handed a JA4+ fingerprint, which is never an
			// address, so the loopback exemption never fired. Check the resolved
			// client address, the same correction made in the reputation blocker.
			clientIP := telemetry.ClientIPOf(r)
			if httputil.IsLoopback(clientIP) || mitigation.IsAllowlisted(clientIP) {
				next.ServeHTTP(w, r)
				return
			}
			// Scoped to the network: delaying every user of a browser because one
			// of them behaved badly is a latency penalty applied to bystanders.
			reputation := telemetry.GetReputationScore(telemetry.GetReputationID(r))
			threatScore := 100.0 - reputation

			if threatScore >= scoreThreshold {
				delay := time.Duration(float64(baseDelay) * (threatScore / scoreThreshold))
				if delay > maxDelay {
					delay = maxDelay
				}
				if delay > 0 {
					time.Sleep(delay)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Entropy middleware calculates Shannon entropy of the request body.
// It uses a non-destructive read to avoid interfering with proxying.
// entropyPeekLimit is how much of a body the entropy check reads. Larger than
// bodyPeekLimit because a Shannon estimate over 64KB of a large upload is not
// a useful signal, and bounded because "measure the body" would otherwise mean
// "hold whatever arrives".
const entropyPeekLimit = 1024 * 1024

func Entropy(threshold float64, routeID string) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checkEntropy(next, w, r, threshold, routeID)
		})
	}
}

func checkEntropy(next http.Handler, w http.ResponseWriter, r *http.Request, threshold float64, routeID string) {
	if httputil.IsLoopback(request.GetClientIP(r, true)) {
		next.ServeHTTP(w, r)
		return
	}

	rs := request.GetRequestState(r)
	if rs != nil && rs.ExecutedEntropy {
		next.ServeHTTP(w, r)
		return
	}

	// A request with no body is not marked executed, which is deliberate
	// rather than an oversight: there was nothing to measure, so a later
	// instance of this middleware in the same chain has lost nothing.
	if r.Body == nil || r.Body == http.NoBody {
		next.ServeHTTP(w, r)
		return
	}

	peeked, err := io.ReadAll(io.LimitReader(r.Body, entropyPeekLimit))
	if err == nil && len(peeked) > 0 {
		// Restore body for downstream.
		r.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
			Closer: r.Body,
		}

		if e := entropy.Calculate(peeked); e > threshold {
			kind.RecordThreat(r, kind.Threat{
				Type:        "high_entropy_payload",
				Score:       (e - threshold) * 20,
				Details:     fmt.Sprintf("High entropy payload detected: %.2f", e),
				RouteID:     routeID,
				Category:    "advanced",
				Severity:    kind.SeverityHigh,
				ActionTaken: kind.ActionDetected,
			})
		}
	}

	if rs != nil {
		rs.ExecutedEntropy = true
	}
	next.ServeHTTP(w, r)
}

func serveTrollResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Send an infinite stream of random-looking data
	// Using a static buffer to avoid allocations in the loop
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	for {
		if _, err := w.Write(buf); err != nil {
			return // Connection closed by client or other error
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(100 * time.Millisecond) // Slow it down a bit to "hang" the tool longer
	}
}

// XSSRecognition middleware scans request for common XSS patterns.
// scanRequestSources feeds the attacker-controlled parts of a request to match,
// cheapest first, and stops at the first hit. It is shared by the three
// recognition middlewares below, which used to carry a copy of this traversal
// each -- three copies that had already drifted, since only two of them looked
// at headers.
//
// The body is peeked under a cap and then put back, so the upstream still
// receives a complete body. bodyPeekLimit bounds what an attacker can make the
// gateway hold: without it, "scan the body" means "buffer whatever arrives".
func scanRequestSources(r *http.Request, includeHeaders bool, match func(data, source string) bool) {
	if r.URL.RawQuery != "" {
		query, _ := url.QueryUnescape(r.URL.RawQuery)
		if match(query, "query string") {
			return
		}
	}

	if includeHeaders {
		for _, h := range recognitionHeaders {
			val := r.Header.Get(h)
			if val == "" {
				continue
			}
			if match(val, "header "+h) {
				return
			}
		}
	}

	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	peeked, err := io.ReadAll(io.LimitReader(r.Body, bodyPeekLimit))
	if err != nil || len(peeked) == 0 {
		return
	}
	// Restore the body for downstream.
	r.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(peeked), r.Body),
		Closer: r.Body,
	}
	match(string(peeked), "request body")
}

// recognitionHeaders are the headers worth scanning: client-written, routinely
// reflected into logs and dashboards, and not otherwise validated.
var recognitionHeaders = [...]string{"User-Agent", "Referer", "X-Forwarded-For"}

// bodyPeekLimit caps how much of a request body a recognition middleware will
// read before deciding. Named rather than repeated at each call site, because
// three copies of a resource bound is three chances to raise one of them.
const bodyPeekLimit = 64 * 1024

// recognition is one pattern-recognition middleware: the corpus it scans for,
// what it calls a hit, and the RequestState flag that stops it running twice
// in a chain that lists it more than once.
type recognition struct {
	routeID    string
	label      string
	threatType string
	category   string
	severity   string
	score      float64
	headers    bool
	find       func(string) []string
	done       func(*request.RequestState) bool
	markDone   func(*request.RequestState)
}

func (rc recognition) middleware() kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc.serve(next, w, r)
		})
	}
}

func (rc recognition) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if httputil.IsLoopback(request.GetClientIP(r, true)) {
		next.ServeHTTP(w, r)
		return
	}

	rs := request.GetRequestState(r)
	if rs != nil && rc.done != nil && rc.done(rs) {
		next.ServeHTTP(w, r)
		return
	}

	var details string
	scanRequestSources(r, rc.headers, func(data, source string) bool {
		matches := rc.find(data)
		if len(matches) == 0 {
			return false
		}
		details = fmt.Sprintf("%s pattern(s) '%s' found in %s",
			rc.label, strings.Join(matches, ", "), source)
		return true
	})

	if details != "" {
		kind.RecordThreat(r, kind.Threat{
			Type:        rc.threatType,
			Score:       rc.score,
			Details:     details,
			RouteID:     rc.routeID,
			Category:    rc.category,
			Severity:    rc.severity,
			ActionTaken: kind.ActionDetected,
		})
	}

	if rs != nil && rc.markDone != nil {
		rc.markDone(rs)
	}

	next.ServeHTTP(w, r)
}

// XSSRecognition middleware scans request for common XSS patterns.
func XSSRecognition(routeID string) kind.Middleware {
	return recognition{
		routeID: routeID, label: "XSS", threatType: "xss_detected",
		category: "xss", severity: kind.SeverityCritical, score: 50, headers: true,
		find:     xssScanner.FindAll,
		done:     func(rs *request.RequestState) bool { return rs.ExecutedXSS },
		markDone: func(rs *request.RequestState) { rs.ExecutedXSS = true },
	}.middleware()
}

// SQLiRecognition middleware scans request for common SQLi patterns.
//
// Headers are deliberately not scanned here, matching the behaviour this
// middleware has always had: a User-Agent carrying `' OR 1=1` is noise on
// nearly every gateway, and the WAF covers the case that is not.
func SQLiRecognition(routeID string) kind.Middleware {
	return recognition{
		routeID: routeID, label: "SQLi", threatType: "sqli_detected",
		category: "sqli", severity: kind.SeverityCritical, score: 60, headers: false,
		find:     sqliScanner.FindAll,
		done:     func(rs *request.RequestState) bool { return rs.ExecutedSQLI },
		markDone: func(rs *request.RequestState) { rs.ExecutedSQLI = true },
	}.middleware()
}

// threatCorpus is one scanner in ThreatRecognition's battery, with the verdict
// a hit produces. Ordered: the first match wins, so the more specific corpora
// have to precede the generic one.
type threatCorpus struct {
	find            func(string) []string
	noun            string
	threatType      string
	severity        string
	queryOrBodyOnly bool
}

var threatCorpora = []threatCorpus{
	{find: genericAttackScanner.FindAll, noun: "Attack", threatType: "generic_attack", severity: kind.SeverityHigh},
	{find: gamblingScanner.FindAll, noun: "Gambling related", threatType: "gambling_detected", severity: kind.SeverityMedium},
	{find: phpScanner.FindAll, noun: "PHP vulnerability", threatType: "php_vulnerability", severity: kind.SeverityCritical},
	// A filename is only suspicious where a filename can do something. In a
	// User-Agent it is a string; in a query or a body it is an upload attempt.
	{find: fileUploadScanner.FindAll, noun: "Malicious file extension", threatType: "file_upload_attempt", severity: kind.SeverityCritical, queryOrBodyOnly: true},
}

// ThreatRecognition middleware scans request for various common attack patterns (RCE, Prototype Pollution, Gambling, PHP vuln, etc.)
func ThreatRecognition(routeID string) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if httputil.IsLoopback(request.GetClientIP(r, true)) {
				next.ServeHTTP(w, r)
				return
			}

			var details, threatType, severity string
			scanRequestSources(r, true, func(data, source string) bool {
				c, matches, ok := matchThreatCorpora(data, source)
				if !ok {
					return false
				}
				threatType, severity = c.threatType, c.severity
				details = fmt.Sprintf("%s pattern(s) '%s' found in %s",
					c.noun, strings.Join(matches, ", "), source)
				return true
			})

			if details != "" {
				kind.RecordThreat(r, kind.Threat{
					Type:        threatType,
					Score:       70,
					Details:     details,
					RouteID:     routeID,
					Category:    "advanced",
					Severity:    severity,
					ActionTaken: kind.ActionDetected,
				})
			}

			next.ServeHTTP(w, r)
		})
	}
}

// matchThreatCorpora returns the first corpus that fires on data.
func matchThreatCorpora(data, source string) (threatCorpus, []string, bool) {
	fromQueryOrBody := strings.Contains(source, "query string") || strings.Contains(source, "body")
	for _, c := range threatCorpora {
		if c.queryOrBodyOnly && !fromQueryOrBody {
			continue
		}
		if matches := c.find(data); len(matches) > 0 {
			return c, matches, true
		}
	}
	return threatCorpus{}, nil, false
}
