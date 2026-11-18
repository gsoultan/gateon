// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// sampledRoute serves requests through a WAF built from cfg, in front of an
// origin that answers what the path asks for, and returns what the shared
// sample then holds for this route.
func sampledRoute(t *testing.T, route string, cfg map[string]string, requests ...*http.Request) string {
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
		_, _ = w.Write([]byte("ok"))
	}))
	for _, r := range requests {
		h.ServeHTTP(httptest.NewRecorder(), r)
	}

	var all bytes.Buffer
	if _, err := corpus.Shared().WriteJSONL(&all); err != nil {
		t.Fatal(err)
	}
	var mine []string
	for line := range strings.SplitSeq(all.String(), "\n") {
		if strings.Contains(line, `"name":"`+route+" ") {
			mine = append(mine, line)
		}
	}
	return strings.Join(mine, "\n")
}

func sampleGet(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
	r.Header.Set("Accept", "text/html")
	return r
}

// A sampling route keeps what it forwarded and the origin accepted, and
// nothing else: not what the WAF refused, and not what the origin refused.
func TestCorpusSample_KeepsOnlyForwardedAcceptedRequests(t *testing.T) {
	got := sampledRoute(t, "sample-on", map[string]string{keyCorpusSampleRate: "1"},
		sampleGet("/shop/items?page=2"),
		sampleGet("/missing/page"),
		sampleGet("/shop/items?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"),
	)
	if !strings.Contains(got, `"target":"/shop/items"`) || !strings.Contains(got, `"page":"2"`) {
		t.Errorf("the accepted request was not kept:\n%s", got)
	}
	if strings.Contains(got, "/missing") {
		t.Errorf("a request the origin answered 404 was kept:\n%s", got)
	}
	if strings.Contains(got, "UNION") {
		t.Errorf("a request the WAF refused was kept:\n%s", got)
	}
}

// Off is the default, and off keeps nothing.
func TestCorpusSample_OffByDefault(t *testing.T) {
	if got := sampledRoute(t, "sample-default", map[string]string{}, sampleGet("/shop/items?page=2")); got != "" {
		t.Errorf("a route with no sample rate kept:\n%s", got)
	}
	if got := sampledRoute(t, "sample-zero", map[string]string{keyCorpusSampleRate: "0"}, sampleGet("/shop/items")); got != "" {
		t.Errorf("a route with a sample rate of 0 kept:\n%s", got)
	}
}

// The credentials a real request carries do not reach the sample.
func TestCorpusSample_CarriesNoCredential(t *testing.T) {
	r := sampleGet("/account?session_token=s3cr3t-value-1234")
	r.Header.Set("Authorization", "Bearer s3cr3t-bearer-5678")
	r.Header.Set("Cookie", "sid=s3cr3t-cookie-9012")
	got := sampledRoute(t, "sample-creds", map[string]string{keyCorpusSampleRate: "1"}, r)
	if !strings.Contains(got, `"target":"/account"`) {
		t.Fatalf("the request was not kept:\n%s", got)
	}
	if strings.Contains(got, "s3cr3t") {
		t.Errorf("the sample carries a credential:\n%s", got)
	}
}

// An upgrade is never sampled: it has no answer to judge it by, and the
// writer must reach the proxy as it is.
func TestCorpusSample_LeavesAnUpgradeAlone(t *testing.T) {
	r := sampleGet("/ws")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if got := sampledRoute(t, "sample-upgrade", map[string]string{keyCorpusSampleRate: "1"}, r); got != "" {
		t.Errorf("an upgrade request was kept:\n%s", got)
	}
}
