// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/schemalearn"
)

// learnedBy serves requests through a WAF built from cfg for route, in front
// of an origin that answers 404 under /missing, and returns the route's draft.
func learnedBy(t *testing.T, route string, cfg map[string]string, requests ...*http.Request) (schemalearn.Draft, bool) {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.WafRules = store
	wafCfg.RouteID = route
	mw, err := WAF(wafCfg)
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		// What a rewrite on the way to the origin does. The draft has to
		// describe what the client sent.
		r.URL.Path = "/internal/rewritten"
		_, _ = w.Write([]byte("ok"))
	}))
	for _, r := range requests {
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	drafts, _ := schemalearn.Shared().Drafts()
	for _, d := range drafts {
		if d.Route == route {
			return d, true
		}
	}
	return schemalearn.Draft{}, false
}

func repeat(n int, target func(i int) string) []*http.Request {
	out := make([]*http.Request, 0, n)
	for i := range n {
		out = append(out, sampleGet(target(i)))
	}
	return out
}

// A learning route drafts a document from what it forwarded and the origin
// accepted: not from what the WAF refused, and not from what the origin did.
func TestSchemaLearning_DraftsFromForwardedAcceptedRequests(t *testing.T) {
	requests := repeat(30, func(i int) string { return "/shop/items/" + strconv.Itoa(100+i) + "?page=" + strconv.Itoa(i) })
	requests = append(requests, repeat(30, func(i int) string { return "/missing/thing?n=" + strconv.Itoa(i) })...)
	requests = append(requests, repeat(30, func(int) string {
		return "/shop/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
	})...)

	d, ok := learnedBy(t, "learn-on", map[string]string{keySchemaLearning: "true"}, requests...)
	if !ok {
		t.Fatal("a learning route has no draft")
	}
	if d.Observed != 30 || d.Operations != 1 {
		t.Fatalf("observed %d requests into %d operations, want 30 into 1:\n%s", d.Observed, d.Operations, d.Document)
	}
	for _, want := range []string{`"/shop/items/{id}"`, `"name": "page"`, `"type": "integer"`} {
		if !strings.Contains(d.Document, want) {
			t.Errorf("the draft lacks %s:\n%s", want, d.Document)
		}
	}
	for _, not := range []string{"/missing", "/shop/search", "/internal/rewritten"} {
		if strings.Contains(d.Document, not) {
			t.Errorf("the draft describes %s:\n%s", not, d.Document)
		}
	}
}

// Off is the default, and a route that is not learning is not in the book.
func TestSchemaLearning_OffByDefault(t *testing.T) {
	if d, ok := learnedBy(t, "learn-default", map[string]string{}, repeat(30, func(int) string { return "/a" })...); ok {
		t.Errorf("a route with learning off has a draft: %+v", d)
	}
	if d, ok := learnedBy(t, "learn-false", map[string]string{keySchemaLearning: "false"}, sampleGet("/a")); ok {
		t.Errorf("a route with learning set to false has a draft: %+v", d)
	}
}

// Learning and sampling share one look at the response, and neither gets in
// the other's way.
func TestSchemaLearning_WorksAlongsideTheRequestSample(t *testing.T) {
	cfg := map[string]string{keySchemaLearning: "true", keyCorpusSampleRate: "1"}
	d, ok := learnedBy(t, "learn-and-sample", cfg, repeat(25, func(i int) string { return "/both?n=" + strconv.Itoa(i) })...)
	if !ok || d.Observed != 25 {
		t.Fatalf("draft %+v, found %v", d, ok)
	}
	if got := sampledRoute(t, "learn-and-sample", cfg); !strings.Contains(got, `"target":"/both"`) {
		t.Errorf("the request sample was not kept while learning:\n%s", got)
	}
}
