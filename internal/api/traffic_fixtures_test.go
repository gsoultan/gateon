// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// traffic is a synthetic population of clients, generated from a fixed seed so
// every run sees the same requests. The detectors' own randomness (the
// isolation forest's) is the only thing that varies between runs, and the
// tests built on this are sized so that it cannot change their outcome.
//
// Addresses are private (10.0.0.0/8): geo enrichment skips them, so no test
// reaches the network.
type traffic struct {
	rng     *rand.Rand
	base    time.Time
	traces  []*telemetry.TraceRecord
	threats []*telemetry.SecurityThreat
}

func newTraffic(seed uint64, base time.Time) *traffic {
	return &traffic{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), base: base}
}

func (tf *traffic) request(ip, method, path, status string, ms float64, at time.Time, ua string) {
	tf.traces = append(tf.traces, &telemetry.TraceRecord{
		SourceIP: ip, Method: method, Path: path, Status: status, DurationMs: ms, Timestamp: at, UserAgent: ua,
	})
}

func (tf *traffic) jitter(minMs, spreadMs int) time.Duration {
	return time.Duration(minMs+tf.rng.IntN(spreadMs)) * time.Millisecond
}

// browsers adds n people reading a site: two to six pages each, every page with
// its assets fetched in a burst, seconds to a minute of reading between pages,
// the odd cached 304 and a missing favicon for about one in three.
func (tf *traffic) browsers(prefix string, n int) []string {
	pages := []string{"/", "/products", "/about", "/pricing", "/blog", "/contact", "/docs", "/login"}
	assets := []string{"/app.js", "/style.css", "/logo.png", "/vendor.js", "/font.woff2", "/icon.svg"}
	ips := make([]string, 0, n)
	for v := range n {
		ip := fmt.Sprintf("%s.%d.%d", prefix, v/200, v%200+1)
		ips = append(ips, ip)
		at := tf.base.Add(time.Duration(tf.rng.IntN(120)) * time.Second)
		for page := range 2 + tf.rng.IntN(5) {
			tf.request(ip, http.MethodGet, pages[tf.rng.IntN(len(pages))], "200", 20+tf.rng.Float64()*120, at, "Mozilla/5.0")
			for a := range 3 + tf.rng.IntN(4) {
				at = at.Add(tf.jitter(10, 200))
				status := "200"
				if page > 0 && tf.rng.IntN(3) == 0 {
					status = "304"
				}
				tf.request(ip, http.MethodGet, assets[a], status, 2+tf.rng.Float64()*30, at, "Mozilla/5.0")
			}
			if page == 0 && tf.rng.IntN(3) == 0 {
				at = at.Add(50 * time.Millisecond)
				tf.request(ip, http.MethodGet, "/favicon.ico", "404", 2, at, "Mozilla/5.0")
			}
			at = at.Add(tf.jitter(5000, 55000))
		}
	}
	return ips
}

// poller adds a client requesting one path every gap, give or take 20ms: a
// dashboard's status poll, a health checker, an uptime monitor.
func (tf *traffic) poller(ip, path string, gap time.Duration, count int) {
	at := tf.base
	for range count {
		tf.request(ip, http.MethodGet, path, "200", 10+tf.rng.Float64()*5, at, "Mozilla/5.0")
		at = at.Add(gap + tf.jitter(-20, 40))
	}
}

// expiredSessionPoller is a dashboard tab left open after its session expired:
// the same GET every gap, answered 401 every time.
func (tf *traffic) expiredSessionPoller(ip, path string, gap time.Duration, count int) {
	at := tf.base
	for range count {
		tf.request(ip, http.MethodGet, path, "401", 3+tf.rng.Float64()*2, at, "Mozilla/5.0")
		at = at.Add(gap + tf.jitter(-20, 40))
	}
}

// ciRunner adds an integration suite walking an API: 80 sequential calls over
// 60 endpoints, one in ten a deliberate 404 and one in ten a deliberate 401.
func (tf *traffic) ciRunner(ip string) {
	at := tf.base
	for i := range 80 {
		status, method := "200", http.MethodGet
		switch i % 10 {
		case 3:
			status = "404"
		case 5:
			status, method = "201", http.MethodPost
		case 7:
			status = "401"
		}
		tf.request(ip, method, fmt.Sprintf("/api/v1/resource-%d", i%60), status, 5+tf.rng.Float64()*150, at, "Go-http-client/1.1")
		at = at.Add(tf.jitter(100, 1500))
	}
}

// natEgress adds one address carrying an office: 800 requests from fifty
// browsers over 150 pages, 3% missing, 1% expired sessions, 11% cached.
func (tf *traffic) natEgress(ip string) {
	at := tf.base
	for i := range 800 {
		status := "200"
		switch r := tf.rng.IntN(100); {
		case r < 3:
			status = "404"
		case r < 4:
			status = "401"
		case r < 15:
			status = "304"
		}
		method := http.MethodGet
		if tf.rng.IntN(20) == 0 {
			method = http.MethodPost
		}
		tf.request(ip, method, fmt.Sprintf("/page-%d", tf.rng.IntN(150)), status, 5+tf.rng.Float64()*200, at,
			fmt.Sprintf("Mozilla/5.0 (user %d)", i%50))
		at = at.Add(time.Duration(tf.rng.ExpFloat64()*700) * time.Millisecond)
	}
}

// scanner adds a vulnerability scanner: n missing paths probed every 100ms,
// and wafBlocks requests the WAF blocked on an attack payload.
func (tf *traffic) scanner(ip string, n, wafBlocks int) {
	at := tf.base
	for r := range n {
		tf.request(ip, http.MethodGet, fmt.Sprintf("/probe-%d.php", r), "404", 2, at, "Mozilla/5.0")
		at = at.Add(100 * time.Millisecond)
	}
	for w := range wafBlocks {
		tf.wafBlock(ip, tf.base.Add(time.Duration(w)*time.Second))
	}
}

// wafBlock records a request the WAF blocked on an attack payload.
func (tf *traffic) wafBlock(ip string, at time.Time) {
	tf.threats = append(tf.threats, &telemetry.SecurityThreat{
		SourceIP: ip, Type: "waf_blocked", Mitigated: true, Time: at, Category: "sqli", ActionTaken: telemetry.ActionBlocked,
	})
}

// classVisitor adds a person loading three pages with a browser of client
// class class (its JA4+), as the trace store records it: JA4 and JA4H, and the
// fingerprint too when behavioural fingerprinting is on.
func (tf *traffic) classVisitor(ip, class string, at time.Time) {
	ja4, ja4h, _ := strings.Cut(class, "_")
	for r, page := range []string{"/", "/app.js", "/style.css"} {
		tf.traces = append(tf.traces, &telemetry.TraceRecord{
			SourceIP: ip, Method: http.MethodGet, Path: page, Status: "200", DurationMs: 20,
			Timestamp: at.Add(time.Duration(r) * time.Second), UserAgent: "Mozilla/5.0",
			JA4: ja4, JA4H: ja4h, Fingerprint: class,
		})
	}
}

// classAttacker adds blocks requests from ip, presenting client class class,
// that the WAF blocked on an attack payload, a second apart from at.
func (tf *traffic) classAttacker(ip, class string, blocks int, at time.Time) {
	for b := range blocks {
		tf.threats = append(tf.threats, &telemetry.SecurityThreat{
			SourceIP: ip, Fingerprint: class, Type: "waf_blocked", Mitigated: true, Category: "sqli",
			ActionTaken: telemetry.ActionBlocked, Time: at.Add(time.Duration(b) * time.Second),
		})
	}
}

// credentialStuffer adds a script POSTing a leaked credential list to /login
// every 600ms or so; one in twenty works.
func (tf *traffic) credentialStuffer(ip string, attempts int) {
	at := tf.base
	for i := range attempts {
		status := "401"
		if i%20 == 0 {
			status = "200"
		}
		tf.request(ip, http.MethodPost, "/login", status, 80+tf.rng.Float64()*10, at, "Mozilla/5.0")
		at = at.Add(tf.jitter(550, 100))
	}
}

// authOutage adds n clients all failing to log in at once -- the identity
// provider is down -- each retrying POST /login every few seconds.
func (tf *traffic) authOutage(prefix string, n int) {
	for v := range n {
		ip := fmt.Sprintf("%s.%d.%d", prefix, v/200, v%200+1)
		at := tf.base.Add(time.Duration(tf.rng.IntN(60)) * time.Second)
		for i := range 12 + tf.rng.IntN(10) {
			status := "401"
			if i%7 == 6 {
				status = "200"
			}
			tf.request(ip, http.MethodPost, "/login", status, 60+tf.rng.Float64()*40, at, "Mozilla/5.0")
			at = at.Add(tf.jitter(2000, 8000))
		}
	}
}

// data is the population as one analysis pass sees it, judged at the end of
// its window.
func (tf *traffic) data() *DiagnosticData {
	return &DiagnosticData{
		Traces:          tf.traces,
		SecurityThreats: tf.threats,
		Now:             tf.base.Add(15 * time.Minute),
	}
}
