// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

type mockWafInvalidator struct {
	called *atomic.Bool
}

func (m *mockWafInvalidator) Invalidate() {
	m.called.Store(true)
	InvalidateWAFCache()
}

func TestWAFCustomRulesDynamicReload(t *testing.T) {
	// 1. Setup DB and WAF Store
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	// Create table
	_, _ = d.Exec(`CREATE TABLE waf_rules (id TEXT PRIMARY KEY, name TEXT, directive TEXT, definition TEXT, format TEXT, conversion_note TEXT, enabled INTEGER, paranoia_level INTEGER, category TEXT, created_at DATETIME, updated_at DATETIME)`)

	store := waf.NewStoreWithDialect(d, dialect)
	called := &atomic.Bool{}
	store.SetInvalidator(&mockWafInvalidator{called: called})

	// 2. Initial WAF config (no rules yet)
	cfg := WAFConfig{
		WafRules: store,
	}

	// 3. Request should pass
	req := httptest.NewRequest("GET", "/?test=1", nil)
	rr := httptest.NewRecorder()

	mw, err := WAF(cfg)
	if err != nil {
		t.Fatalf("WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// 4. Add a rule that blocks "test=1".
	//
	// The stored form is a typed definition rather than SecLang, and the ID is
	// in the engine's embedder range: a stored rule below it is refused rather
	// than silently renumbered into a range the engine reserves for itself.
	err = store.AddRule(t.Context(), &waf.Rule{
		ID:   "1000000",
		Name: "Block Test 1",
		Definition: `{"phase":"request_body","targets":["args:test"],
			"operator":{"kind":"equals","pattern":"1"},
			"severity":"critical","confidence":"certain",
			"msg":"Block Test 1","status":403,"tags":["test"]}`,
		Format:  waf.FormatGateon,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if !called.Load() {
		t.Error("Expected invalidator to be called")
	}

	// 5. Re-evaluate the same middleware logic.
	// In the real app, the server would rebuild the middleware chain when it receives the invalidation signal.
	// Here we simulate that by calling WAF(cfg) again.

	mw2, err := WAF(cfg)
	if err != nil {
		t.Fatalf("WAF2: %v", err)
	}

	handler2 := mw2(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr2 := httptest.NewRecorder()
	handler2.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("expected 403 after adding rule, got %d", rr2.Code)
	}
}

func TestWAF_BodyRestoration(t *testing.T) {
	cfg := WAFConfig{
		ExtraRules: rules.Set{{
			ID:       1001001,
			Phase:    types.PhaseRequestBody,
			Targets:  []types.Target{{Kind: types.TargetRequestBody}},
			Op:       op.Contains("Hello"),
			Actions:  []rules.Action{rules.Log},
			Severity: types.SeverityNotice, Confidence: types.Certain,
			Msg: "body restoration probe",
		}},
	}

	mw, err := WAF(cfg)
	if err != nil {
		t.Fatalf("Failed to create WAF: %v", err)
	}

	bodyContent := "Hello, WAF!"
	req := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte(bodyContent)))
	req.Header.Set("Content-Type", "text/plain")

	var capturedBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body in next handler: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}

	if string(capturedBody) != bodyContent {
		t.Errorf("Body was consumed and not restored. Expected %q, got %q", bodyContent, string(capturedBody))
	}
}
