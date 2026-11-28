// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf/features"
)

// fakeMimir answers Predict with chance for every row, and Explain with
// columns, and records what it was asked.
type fakeMimir struct {
	chance  float64
	columns []string
	status  int
	asked   atomic.Int32
	lastReq atomic.Pointer[map[string]any]
	auth    atomic.Pointer[string]
}

func (f *fakeMimir) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.asked.Add(1)
	a := r.Header.Get("Authorization")
	f.auth.Store(&a)
	var req map[string]any
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.lastReq.Store(&req)
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	switch r.URL.Path {
	case predictPath:
		_ = json.NewEncoder(w).Encode(map[string]any{"guesses": []map[string]any{
			{"label": features.LabelAttack, "probability": f.chance},
			{"label": features.LabelClean, "probability": 1 - f.chance},
		}})
	case explainPath:
		var cs []map[string]any
		for _, c := range f.columns {
			cs = append(cs, map[string]any{"column": c, "effect": 0.2})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"contributions": cs})
	default:
		http.NotFound(w, r)
	}
}

func mimirWorker(t *testing.T, f http.Handler) *Worker {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	w := newWorker(t)
	if err := w.UseMimir(MimirConfig{URL: srv.URL, Model: "m1", Key: "mimir-key", Threshold: 80}, 4); err != nil {
		t.Fatal(err)
	}
	return w
}

func judgeAll(t *testing.T, w *Worker, samples ...*Sample) []Verdict {
	t.Helper()
	body, _ := json.Marshal(Batch{Samples: samples})
	req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer worker-token")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("worker answered %d: %s", rec.Code, rec.Body.String())
	}
	var a Answer
	if err := json.NewDecoder(rec.Body).Decode(&a); err != nil {
		t.Fatal(err)
	}
	return a.Verdicts
}

func withID(s *Sample, id string) *Sample { s.ID = id; return s }

// A model that is sure is a verdict, labelled as the model's and with the
// columns that moved it, and mimir is asked with the key and every column.
func TestTheMimirJudgeFlagsWhatTheModelIsSureOf(t *testing.T) {
	f := &fakeMimir{chance: 0.93, columns: []string{"hits_sqli", "made_up_column", "entropy_longest"}}
	w := mimirWorker(t, f)
	vs := judgeAll(t, w, withID(sampleOf(t, injection, "203.0.113.9"), "1"))
	if len(vs) != 1 || vs[0].ID != "1" || vs[0].Label != mimirLabel || vs[0].Score != 93 {
		t.Fatalf("verdicts %+v", vs)
	}
	if !strings.Contains(vs[0].Reason, "hits_sqli, entropy_longest") || strings.Contains(vs[0].Reason, "made_up") {
		t.Errorf("reason %q names a column that is not ours, or misses one that is", vs[0].Reason)
	}
	if got := *f.auth.Load(); got != "Bearer mimir-key" {
		t.Errorf("authorization %q", got)
	}
	fields, _ := (*f.lastReq.Load())["fields"].(map[string]any)
	if len(fields) != len(features.Columns) {
		t.Errorf("mimir was asked with %d columns, want %d", len(fields), len(features.Columns))
	}
	for name, v := range fields {
		if s, _ := v.(string); strings.Contains(s, "UNION") || strings.Contains(s, "203.0.113.9") {
			t.Errorf("column %s carries the client's text or address: %q", name, s)
		}
	}
}

// The point of the model is precision: when it is not sure, there is no
// verdict, even though paranoia 4 would have flagged the request.
func TestTheMimirJudgeIsQuietWhenTheModelIsNotSure(t *testing.T) {
	w := mimirWorker(t, &fakeMimir{chance: 0.4})
	if vs := judgeAll(t, w, withID(sampleOf(t, injection, "203.0.113.9"), "1")); len(vs) != 0 {
		t.Fatalf("verdicts %+v", vs)
	}
}

// A model that does not answer, or answers with something other than an
// answer, costs the second opinion its precision and nothing else: the
// rules judge, as the reference worker does.
func TestTheMimirJudgeFallsBackToTheRules(t *testing.T) {
	cases := map[string]http.Handler{
		"error":    &fakeMimir{status: http.StatusInternalServerError},
		"redirect": http.RedirectHandler("http://127.0.0.1:1/elsewhere", http.StatusFound),
		"garbage": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte("x"), mimirMaxAnswer+1))
		}),
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			w := mimirWorker(t, h)
			vs := judgeAll(t, w,
				withID(sampleOf(t, injection, "203.0.113.9"), "attack"),
				withID(sampleOf(t, "/items/7?page=2", "203.0.113.9"), "clean"))
			if len(vs) != 1 || vs[0].ID != "attack" || vs[0].Label == mimirLabel || !strings.HasPrefix(vs[0].Reason, "rule ") {
				t.Fatalf("verdicts %+v, want the rules' verdict on the attack alone", vs)
			}
		})
	}
}

func TestTheMimirJudgeRefusesAnUnsafeConfiguration(t *testing.T) {
	ok := MimirConfig{URL: "https://mimir.example.com", Model: "m1", Key: "k", Threshold: 80}
	for name, mutate := range map[string]func(*MimirConfig){
		"plain http off host": func(c *MimirConfig) { c.URL = "http://mimir.example.com" },
		"credential in url":   func(c *MimirConfig) { c.URL = "https://u:p@mimir.example.com" },
		"no model":            func(c *MimirConfig) { c.Model = " " },
		"no key":              func(c *MimirConfig) { c.Key = "" },
		"threshold 0":         func(c *MimirConfig) { c.Threshold = 0 },
		"threshold 101":       func(c *MimirConfig) { c.Threshold = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			mutate(&c)
			if _, err := newMimirJudge(c, 4); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := newMimirJudge(ok, 4); err != nil {
		t.Fatalf("a good configuration was refused: %v", err)
	}
}

func TestScoreOfStaysInRange(t *testing.T) {
	for in, want := range map[float64]int{-1: 0, 0: 0, 0.805: 81, 1: 100, 7: 100} {
		if got := scoreOf(in); got != want {
			t.Errorf("scoreOf(%v) = %d, want %d", in, got, want)
		}
	}
}
