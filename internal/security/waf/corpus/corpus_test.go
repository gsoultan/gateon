// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package corpus_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/security/redact"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
	"github.com/gsoultan/gwaf/calibrate"
)

// A PASETO-shaped value, which redact recognises wherever it appears.
const pasetoLike = "v4.public.eyJzdWIiOiJhbGljZSIsImV4cCI6IjIwMjYtMTItMDFUMDA6MDA6MDBaIn0" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func request(target string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// The property the sample has to keep: no credential leaves the gateway in
// it, whether a name gives it away or only its shape does.
func TestCaptureKeepsNoCredential(t *testing.T) {
	secrets := []string{"hunter2-session", "Bearer abc.def.ghi", "sk_live_51Habcdefgh", pasetoLike}
	r := request("/api/orders?page=2&access_token=hunter2-session&next="+pasetoLike, map[string]string{
		"Authorization": "Bearer abc.def.ghi",
		"Cookie":        "sid=hunter2-session",
		"X-Api-Key":     "sk_live_51Habcdefgh",
		"X-Forwarded":   pasetoLike,
		"Accept":        "application/json",
	})
	e, ok := corpus.Capture(r, "orders")
	if !ok {
		t.Fatal("an ordinary request was not captured")
	}

	ring := corpus.NewRing(4)
	ring.Add(e)
	var out bytes.Buffer
	if _, err := ring.WriteJSONL(&out); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(out.String(), s) {
			t.Errorf("the sample contains a credential %q:\n%s", s, out.String())
		}
	}

	if e.Args["page"] != "2" || e.Headers["Accept"] != "application/json" {
		t.Errorf("ordinary values were not kept as sent: %+v", e)
	}
	// The name survives, because an exception is scoped to it.
	if e.Args["access_token"] != redact.Mask || e.Args["next"] != redact.Mask {
		t.Errorf("credential parameters were not masked under their names: %+v", e.Args)
	}
	if e.Target != "/api/orders" || e.Method != http.MethodGet {
		t.Errorf("target %q method %q", e.Target, e.Method)
	}
}

// A request past a bound is left out whole. A truncated value is one the
// client never sent.
func TestCaptureLeavesOutWhatDoesNotFit(t *testing.T) {
	big := strings.Repeat("a", corpus.MaxEntryBytes)
	if _, ok := corpus.Capture(request("/x?q="+big, nil), "r"); ok {
		t.Error("a request larger than an entry was captured")
	}
	if _, ok := corpus.Capture(request("/"+big, nil), "r"); ok {
		t.Error("a path larger than an entry was captured")
	}
	many := "/x?"
	for i := range 60 {
		many += "p" + strconv.Itoa(i) + "=1&"
	}
	if _, ok := corpus.Capture(request(many, nil), "r"); ok {
		t.Error("a request with more parameters than an entry holds was captured")
	}
}

// What the gateway exports is what gwaf's toolchain reads. This is the
// contract between the two, checked against gwaf's own loader.
func TestTheSampleIsACorpusGwafLoads(t *testing.T) {
	ring := corpus.NewRing(8)
	for i := range 3 {
		e, _ := corpus.Capture(request("/api/orders/"+strconv.Itoa(i)+"?page=1", map[string]string{"Accept": "*/*"}), "orders")
		ring.Add(e)
	}
	var out bytes.Buffer
	n, err := ring.WriteJSONL(&out)
	if err != nil || n != 3 {
		t.Fatalf("wrote %d entries, err %v", n, err)
	}
	got, err := calibrate.LoadCorpus(&out)
	if err != nil {
		t.Fatalf("gwaf does not load the export: %v", err)
	}
	if len(got) != 3 || got[0].Method != "GET" || got[0].Target != "/api/orders/0" ||
		got[0].Args["page"] != "1" || got[0].Headers["Accept"] != "*/*" || got[0].Name == "" {
		t.Errorf("loaded %+v", got)
	}
}

func TestRingKeepsTheNewestAndNoMore(t *testing.T) {
	ring := corpus.NewRing(4)
	for i := range 10 {
		ring.Add(&corpus.Entry{Name: strconv.Itoa(i)})
	}
	if ring.Len() != 4 || ring.Total() != 10 {
		t.Fatalf("len %d total %d, want 4 and 10", ring.Len(), ring.Total())
	}
	var out bytes.Buffer
	_, _ = ring.WriteJSONL(&out)
	for _, want := range []string{`"6"`, `"7"`, `"8"`, `"9"`} {
		if !strings.Contains(out.String(), `"name":`+want) {
			t.Errorf("entry %s was displaced:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), `"name":"5"`) {
		t.Error("an entry older than the ring's size is still held")
	}
}

func TestRingIsSafeUnderConcurrentWriters(t *testing.T) {
	ring := corpus.NewRing(16)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for i := range 500 {
				if ring.Due(3) {
					ring.Add(&corpus.Entry{Name: strconv.Itoa(i)})
				}
				_, _ = ring.WriteJSONL(&bytes.Buffer{})
			}
		})
	}
	wg.Wait()
	if ring.Len() != 16 {
		t.Errorf("len %d, want a full ring", ring.Len())
	}
}

func TestDueSamplesOneInRate(t *testing.T) {
	ring := corpus.NewRing(1)
	hits := 0
	for range 1000 {
		if ring.Due(10) {
			hits++
		}
	}
	if hits != 100 {
		t.Errorf("%d of 1000 sampled at one in ten", hits)
	}
	if ring.Due(0) || ring.Due(-1) {
		t.Error("a rate below one sampled a request")
	}
	for _, bad := range []string{"", "0", "-5", "ten", "1.5"} {
		if corpus.ParseRate(bad) != 0 {
			t.Errorf("ParseRate(%q) is not 0", bad)
		}
	}
	if corpus.ParseRate("100") != 100 {
		t.Error("ParseRate(100)")
	}
}

func TestStatusWriterReportsTheAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		serve func(w http.ResponseWriter)
		want  int
	}{
		"explicit":      {func(w http.ResponseWriter) { w.WriteHeader(404) }, 404},
		"body only":     {func(w http.ResponseWriter) { _, _ = w.Write([]byte("x")) }, 200},
		"nothing":       {func(http.ResponseWriter) {}, 0},
		"informational": {func(w http.ResponseWriter) { w.WriteHeader(103); w.WriteHeader(201) }, 201},
	} {
		sw := corpus.Watch(httptest.NewRecorder())
		tc.serve(sw)
		if sw.Status() != tc.want {
			t.Errorf("%s: status %d, want %d", name, sw.Status(), tc.want)
		}
	}
	if corpus.Accepted(0) || corpus.Accepted(404) || corpus.Accepted(500) || !corpus.Accepted(204) || !corpus.Accepted(302) {
		t.Error("Accepted draws the line somewhere other than 2xx and 3xx")
	}
}

func TestExport(t *testing.T) {
	body := `{"name":"a","method":"GET","target":"/"}` + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != corpus.Path:
			w.WriteHeader(http.StatusNotFound)
		case r.Header.Get("Authorization") == "Bearer empty":
		case r.Header.Get("Authorization") == "Bearer viewer":
			w.WriteHeader(http.StatusForbidden)
		case r.Header.Get("Authorization") != "Bearer good":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte(body))
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := corpus.Export(context.Background(), srv.URL, "good", &out); err != nil || out.String() != body {
		t.Errorf("export wrote %q, err %v", out.String(), err)
	}
	if err := corpus.Export(context.Background(), srv.URL, "empty", &bytes.Buffer{}); !errors.Is(err, corpus.ErrEmpty) {
		t.Errorf("an empty sample answered %v, want ErrEmpty", err)
	}
	for token, want := range map[string]string{"": "401", "viewer": "403"} {
		err := corpus.Export(context.Background(), srv.URL, token, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("token %q: %v, want an error naming %s", token, err, want)
		}
	}
}
