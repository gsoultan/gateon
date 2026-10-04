// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/request"
	wafstore "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

// leakPath is where auditedWAF's backend answers with an AWS access key in
// the body, for the response-phase data-leak rules to find.
const leakPath = "/leak"

// auditedWAF builds an enforcing WAF, data-leak rules on, whose audit log is
// written to a file the test reads.
func auditedWAF(t *testing.T, auditPath string) http.Handler {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := wafstore.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		RouteID: "audit-redact", WafRules: store, ParanoiaLevel: 1, AnomalyThreshold: 5,
		RequestBodyLimit: 1 << 20, ResponseBodyLimit: 1 << 20, DisableWordPress: true,
		EnableDLP: true, EnableResponseInspection: true, AuditLogPath: auditPath,
		ExtraRules: markerRules(),
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == setCookiePath {
			w.Header().Set("Set-Cookie", "sid=S3CRET-RESPMARK")
		}
		if r.URL.Path == leakPath {
			_, _ = w.Write([]byte(`{"message":"deploy key is AKIAIOSFODNN7EXAMPLE"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

// setCookiePath is where auditedWAF's backend sets a session cookie.
const setCookiePath = "/session"

// markerRules are operator rules -- the kind a custom rule definition
// compiles to -- that reach collections the shipped ruleset does not target:
// every argument, and the response headers. Each refuses on a marker.
// (REQUEST_COOKIES, ARGS_GET and ARGS_JOINED are absent: under gwaf v0.6.2 a
// rule on any of them did not fire for these requests, so matchedInCredential's
// handling of them is defensive and not exercised here.)
func markerRules() rules.Set {
	rule := func(id types.RuleID, phase types.Phase, kind types.TargetKind, marker string) rules.Rule {
		return rules.Rule{
			ID: id, Phase: phase, Targets: []types.Target{{Kind: kind}}, Op: op.Contains(marker),
			Actions: []rules.Action{rules.Block}, Severity: types.SeverityCritical, Confidence: types.Certain,
			Msg: "marker " + marker,
		}
	}
	// A body argument's whole value, when it carries the marker: the span is
	// the value, which is all the record has to judge a body argument by.
	whole := rule(1001105, types.PhaseRequestBody, types.TargetArgs, "")
	whole.Op = op.Func("bodymark", func(v []byte) bool { return strings.Contains(string(v), "BODYMARK") })
	return rules.Set{
		rule(1001103, types.PhaseRequestHeaders, types.TargetArgs, "ARGMARK"),
		rule(1001104, types.PhaseResponseHeaders, types.TargetResponseHeaders, "RESPMARK"),
		whole,
	}
}

// auditLines sends one request and returns the audit lines it added, failing
// on any that carries a credential.
func auditLines(t *testing.T, h http.Handler, path string, r *http.Request) []auditRecord {
	t.Helper()
	before, _ := os.ReadFile(path)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")
	r = r.WithContext(context.WithValue(r.Context(), request.RequestStateContextKey{}, &request.RequestState{}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var recs []auditRecord
	for _, line := range strings.Split(strings.TrimSpace(string(after[len(before):])), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "S3CRET") || strings.Contains(line, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("an audit line carries the credential:\n%s", line)
		}
		var rec auditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not JSON: %v\n%s", err, line)
		}
		recs = append(recs, rec)
	}
	if len(recs) == 0 || recs[len(recs)-1].RuleID == "" {
		t.Fatalf("the request was not audited as a match: %+v", recs)
	}
	return recs
}

// sqli is matched by the structural SQL-injection rule wherever it appears.
const sqli = "' UNION SELECT password FROM users--"

// get builds a GET with the given headers.
func get(target string, header ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return r
}

// post builds a POST with the given content type and body.
func post(target, contentType, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	return r
}

// TestTheWAFAuditLogRecordsWhereACredentialMatchedNotWhatItSaid: the audit
// log copies up to 256 bytes of the value a rule matched, and when that value
// is an app's session cookie, its Authorization header or a token parameter,
// those bytes are the credential -- written to a file shipped to a SIEM. A
// match inside one is recorded by rule, location and length; the URI keeps
// its parameter names and loses credential values. A match anywhere else still
// shows its bytes, which is what makes a false positive fixable.
func TestTheWAFAuditLogRecordsWhereACredentialMatchedNotWhatItSaid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	h := auditedWAF(t, path)
	plus := strings.ReplaceAll(sqli, " ", "+")
	jwt := "eyJhbGciOiJub25lIn0.eyJTM0NSRVQiOjF9." + plus

	cases := []struct {
		name     string
		req      *http.Request
		withheld bool
	}{
		{"cookie", get("/app?q=visible-param", "Cookie", "sid=S3CRET"+sqli), true},
		{"authorization", get("/app?q=visible-param", "Authorization", "Bearer S3CRET"+sqli), true},
		{"token parameter", get("/app?q=visible-param&token=S3CRET" + plus), true},
		{"credential-shaped value", get("/app?q=visible-param&v=" + jwt), true},
		{"referer naming a token", get("/app?q=visible-param", "Referer", "https://a.example/?token=S3CRET"+plus), true},
		{"form password", post("/login?q=visible-param", "application/x-www-form-urlencoded", "user=bob&password=S3CRET"+plus), true},
		{"raw body quoting a bearer token", post("/x?q=visible-param", "text/plain", "Authorization: Bearer S3CRET"+sqli), true},
		{"data leak in the response", get(leakPath + "?q=visible-param"), true},
		{"operator rule on a credential-shaped argument", get("/app?q=visible-param&v=eyJhbGciOi.eyJTM0NS.S3CRET-ARGMARK"), true},
		{"operator rule on a response's Set-Cookie", get(setCookiePath + "?q=visible-param"), true},
		{"operator rule on a credential-shaped body argument", post("/app?q=visible-param", "application/x-www-form-urlencoded",
			"v=eyJhbGciOi.eyJTM0NS.S3CRET-BODYMARK"), true},
		{"operator rule on an ordinary body argument keeps its bytes", post("/app?q=visible-param", "application/x-www-form-urlencoded",
			"v=BODYMARK"), false},
		{"operator rule on an ordinary argument keeps its bytes", get("/app?q=visible-param&v=ARGMARK"), false},
		{"an ordinary parameter keeps its bytes", get("/app?q=" + plus), false},
		{"an ordinary raw body keeps its bytes", post("/x?q=visible-param", "text/plain", "note"+sqli), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs := auditLines(t, h, path, tc.req)
			rec := recs[len(recs)-1]
			t.Logf("target=%s key=%s", rec.Target, rec.Key)
			if tc.withheld && (rec.MatchedBytes != "" || !rec.MatchedBytesWithheld) {
				t.Errorf("matched_bytes = %q, withheld = %v: a match in a credential kept its bytes",
					rec.MatchedBytes, rec.MatchedBytesWithheld)
			}
			if !tc.withheld && (rec.MatchedBytes == "" || rec.MatchedBytesWithheld) {
				t.Errorf("matched_bytes = %q, withheld = %v: a match outside any credential lost its bytes",
					rec.MatchedBytes, rec.MatchedBytesWithheld)
			}
			if rec.MatchedAt == nil || rec.MatchedAt.Length == 0 {
				t.Errorf("matched_at = %+v: the record lost where and how long the match was", rec.MatchedAt)
			}
			if strings.Contains(tc.req.RequestURI, "visible-param") && !strings.Contains(rec.URI, "q=visible-param") {
				t.Errorf("uri = %q lost a parameter that is not a credential", rec.URI)
			}
		})
	}
}
