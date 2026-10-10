// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
)

// customTargetStatus is the status every probe rule refuses with. It is one no
// built-in rule uses, so a refusal carrying it can only have come from the
// probe rule, and a request some other rule happened to block cannot make a
// case pass.
const customTargetStatus = http.StatusUnavailableForLegalReasons

// customTargetCase is one stored-rule target, a request that must trip a rule
// on it and a request that must not.
//
// The miss request is chosen to carry the probe somewhere *else*, wherever
// that is meaningful: in the query for a cookie rule, in the body for a query
// rule, in another cookie for a rule naming one cookie. A miss that simply
// omits the probe would let a target that reads the wrong collection pass.
type customTargetCase struct {
	target  string
	phase   string
	opKind  string
	pattern string
	hit     func() *http.Request
	miss    func() *http.Request
}

func getReq(target string) func() *http.Request {
	return func() *http.Request { return httptest.NewRequest(http.MethodGet, target, nil) }
}

func withHeader(target, name, value string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set(name, value)
		return r
	}
}

func postReq(target, contentType, body string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		return r
	}
}

const formType = "application/x-www-form-urlencoded"

// requestTargetCases covers every request-side collection a stored rule can
// name in internal/security/waf/ruledef.go targetKinds.
func requestTargetCases() []customTargetCase {
	return []customTargetCase{
		{target: "method", opKind: "equals", pattern: "DELETE",
			hit:  func() *http.Request { return httptest.NewRequest(http.MethodDelete, "/", nil) },
			miss: getReq("/?m=DELETE")},
		{target: "uri", hit: getReq("/x?gwafprobe"), miss: withHeader("/x", "X-Probe", "gwafprobe")},
		{target: "path", hit: getReq("/gwafprobe"), miss: getReq("/x?q=gwafprobe")},
		{target: "protocol", opKind: "equals", pattern: "HTTP/1.0",
			hit: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0
				return r
			},
			miss: getReq("/?p=HTTP/1.0")},
		{target: "headers:x-probe", hit: withHeader("/", "X-Probe", "gwafprobe"), miss: withHeader("/", "X-Other", "gwafprobe")},
		{target: "header_names", hit: withHeader("/", "X-Gwafprobe", "1"), miss: withHeader("/", "X-Other", "gwafprobe")},
		{target: "args:q", hit: getReq("/?q=gwafprobe"), miss: getReq("/?r=gwafprobe")},
		{target: "arg_names", hit: getReq("/?gwafprobe=1"), miss: getReq("/?a=gwafprobe")},
		// The body phase, so the miss has body arguments to be wrongly read.
		{target: "args_get", phase: "request_body",
			hit: getReq("/?q=gwafprobe"), miss: postReq("/", formType, "q=gwafprobe")},
		{target: "args_get:q", hit: getReq("/?q=gwafprobe"), miss: getReq("/?r=gwafprobe")},
		{target: "args_post", phase: "request_body",
			hit: postReq("/", formType, "q=gwafprobe"), miss: getReq("/?q=gwafprobe")},
		{target: "body", phase: "request_body",
			hit: postReq("/", "text/plain", "gwafprobe"), miss: getReq("/?q=gwafprobe")},
		{target: "cookies", hit: withHeader("/", "Cookie", "a=1; sid=gwafprobe"), miss: getReq("/?sid=gwafprobe")},
		{target: "cookies:sid", hit: withHeader("/", "Cookie", "a=1; sid=gwafprobe"),
			miss: withHeader("/", "Cookie", "sid=x; other=gwafprobe")},
		{target: "cookie_names", hit: withHeader("/", "Cookie", "gwafprobe=1"), miss: withHeader("/", "Cookie", "a=gwafprobe")},
		{target: "remote_addr", pattern: "192.0.2.77",
			hit: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = "192.0.2.77:1234"
				return r
			},
			miss: getReq("/?a=192.0.2.77")},
		{target: "args_joined", phase: "request_body", hit: getReq("/?a=gwafprobe"), miss: withHeader("/", "X-Probe", "gwafprobe")},
		{target: "resolved:origin.amp", opKind: "equals", pattern: waf.OriginAMPMismatch,
			hit:  getReq("http://example.com/?__amp_source_origin=https://evil.example"),
			miss: getReq("http://example.com/?__amp_source_origin=https://example.com")},
	}
}

// probeBackend answers with whatever the request asks for, so the response
// collections can be given a value the probe rule matches.
func probeBackend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if v := q.Get("hval"); v != "" {
		w.Header().Set("X-Out", v)
	}
	if v := q.Get("hname"); v != "" {
		w.Header().Set(v, "1")
	}
	status := http.StatusOK
	if v := q.Get("status"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			status = n
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("body:" + q.Get("body")))
}

// responseTargetCases covers the response-side collections.
func responseTargetCases() []customTargetCase {
	return []customTargetCase{
		{target: "resp_status", phase: "response_headers", opKind: "equals", pattern: "418",
			hit: getReq("/?status=418"), miss: getReq("/?status=200&s=418")},
		{target: "resp_headers:x-out", phase: "response_headers",
			hit: getReq("/?hval=gwafprobe"), miss: getReq("/?s=gwafprobe")},
		{target: "resp_hdr_name", phase: "response_headers",
			hit: getReq("/?hname=X-Gwafprobe"), miss: getReq("/?hval=gwafprobe")},
		{target: "resp_body", phase: "response_body",
			hit: getReq("/?body=gwafprobe"), miss: getReq("/?hval=gwafprobe")},
	}
}

// customTargetWAF builds the real WAF middleware over a store holding one
// rule on c's target, exactly as an operator's dashboard-authored rule loads.
func customTargetWAF(t *testing.T, c customTargetCase) http.Handler {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`CREATE TABLE waf_rules (id TEXT PRIMARY KEY, name TEXT, directive TEXT, definition TEXT, format TEXT, conversion_note TEXT, enabled INTEGER, paranoia_level INTEGER, category TEXT, created_at DATETIME, updated_at DATETIME)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	store := waf.NewStoreWithDialect(d, dialect)

	phase, kind, pattern := c.phase, c.opKind, c.pattern
	if phase == "" {
		phase = "request_headers"
	}
	if kind == "" {
		kind = "contains"
	}
	if pattern == "" {
		pattern = "gwafprobe"
	}
	def := fmt.Sprintf(`{"phase":%q,"targets":[%q],"operator":{"kind":%q,"pattern":%q},`+
		`"severity":"critical","confidence":"certain","msg":"probe %s","status":%d}`,
		phase, c.target, kind, pattern, c.target, customTargetStatus)
	if err := store.AddRule(t.Context(), &waf.Rule{
		ID: "1000000", Name: "probe " + c.target, Definition: def,
		Format: waf.FormatGateon, Enabled: true,
	}); err != nil {
		t.Fatalf("AddRule %s: %v", def, err)
	}

	mw, err := WAF(WAFConfig{WafRules: store, EnableResponseInspection: true})
	if err != nil {
		t.Fatalf("WAF: %v", err)
	}
	return mw(http.HandlerFunc(probeBackend))
}

// TestWAFCustomRuleTargetsFire proves a stored rule on each target refuses a
// request carrying the probe in that collection and lets through one carrying
// it anywhere else.
//
// It exists because rules on cookies and args_get compiled, saved, showed as
// enabled in the dashboard, and never matched anything: gwaf v0.6.2 defines
// those collections but never fills them.
func TestWAFCustomRuleTargetsFire(t *testing.T) {
	cases := append(requestTargetCases(), responseTargetCases()...)
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			h := customTargetWAF(t, c)

			hit := httptest.NewRecorder()
			h.ServeHTTP(hit, c.hit())
			if hit.Code != customTargetStatus {
				t.Errorf("a rule on %s did not fire on a request carrying the probe there: status %d, want %d",
					c.target, hit.Code, customTargetStatus)
			}

			miss := httptest.NewRecorder()
			h.ServeHTTP(miss, c.miss())
			if miss.Code == customTargetStatus {
				t.Errorf("a rule on %s fired on a request carrying the probe only outside it", c.target)
			}
		})
	}
}
