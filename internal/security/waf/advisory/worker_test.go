// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const injection = "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"

func newWorker(t *testing.T) *Worker {
	t.Helper()
	w, err := NewWorker("worker-token", 4)
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	return w
}

// The reference worker names the rule that would have refused a request, and
// has nothing to say about an ordinary one.
func TestTheReferenceWorkerFlagsAnAttackAndNamesTheRule(t *testing.T) {
	w := newWorker(t)
	attack := sampleOf(t, injection, "203.0.113.9")
	attack.ID = "1"
	v, flagged := w.Judge(attack)
	if !flagged {
		t.Fatal("an injection was not flagged")
	}
	if v.ID != "1" || v.Score < 1 || !strings.HasPrefix(v.Reason, "rule ") || !isLabel(v.Label) {
		t.Errorf("verdict %+v", v)
	}

	for _, target := range []string{"/", "/items/7?page=2&sort=name", "/blog/2026/hello-world"} {
		clean := sampleOf(t, target, "203.0.113.9")
		if v, flagged := w.Judge(clean); flagged {
			t.Errorf("%s was flagged: %+v", target, v)
		}
	}
}

// What the gateway's own rules already matched is already in the Security
// Hub. The worker does not say it again.
func TestTheReferenceWorkerDoesNotRepeatTheGatewaysOwnMatch(t *testing.T) {
	w := newWorker(t)
	attack := sampleOf(t, injection, "203.0.113.9")
	v, flagged := w.Judge(attack)
	if !flagged {
		t.Fatal("an injection was not flagged")
	}
	rule := strings.Fields(strings.TrimPrefix(v.Reason, "rule "))[0]
	var id uint32
	if err := json.Unmarshal([]byte(rule), &id); err != nil {
		t.Fatalf("no rule number in %q", v.Reason)
	}
	attack.Rules = []uint32{id}
	if v, flagged := w.Judge(attack); flagged {
		t.Errorf("the gateway's own match was repeated: %+v", v)
	}
}

func post(w *Worker, path, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r)
	return rec
}

func TestTheReferenceWorkerAnswersOnlyAGatewayThatHasItsToken(t *testing.T) {
	w := newWorker(t)
	s := sampleOf(t, injection, "203.0.113.9")
	s.ID = "7"
	body, _ := json.Marshal(Batch{Samples: []*Sample{s}})

	for _, token := range []string{"", "wrong", "worker-token-and-more"} {
		if rec := post(w, Path, token, body); rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status %d", token, rec.Code)
		}
	}
	if rec := post(w, "/elsewhere", "worker-token", body); rec.Code != http.StatusNotFound {
		t.Errorf("another path: status %d", rec.Code)
	}
	if rec := post(w, Path, "worker-token", []byte("not json")); rec.Code != http.StatusBadRequest {
		t.Errorf("a body that is not a batch: status %d", rec.Code)
	}
	huge := append([]byte(`{"samples":[],"pad":"`), bytes.Repeat([]byte("a"), maxBatchBytes)...)
	if rec := post(w, Path, "worker-token", append(huge, '"', '}')); rec.Code != http.StatusBadRequest {
		t.Errorf("a body past the limit: status %d", rec.Code)
	}

	rec := post(w, Path, "worker-token", body)
	var a Answer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if len(a.Verdicts) != 1 || a.Verdicts[0].ID != "7" {
		t.Errorf("verdicts %+v", a.Verdicts)
	}
	if _, err := NewWorker("", 4); err == nil {
		t.Error("a worker with no token was built")
	}
}

// The two halves speak the same exchange: a gateway's queue in front of the
// reference worker gets the attack flagged and the ordinary request not.
func TestTheQueueAndTheReferenceWorkerAgreeOnTheExchange(t *testing.T) {
	q, findings := running(t, newWorker(t), Config{Capacity: 8, Token: "worker-token", BatchSize: 2})
	q.Offer(sampleOf(t, "/items/7?page=2", "198.51.100.4"))
	q.Offer(sampleOf(t, injection, "203.0.113.9"))

	f := wait(t, findings, "the verdict")
	if f.Sample.Source.Addr != "203.0.113.9" || f.Sample.Target != "/search" {
		t.Errorf("the verdict is for %+v %s", f.Sample.Source, f.Sample.Target)
	}
}
