package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
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
	_, _ = d.Exec(`CREATE TABLE waf_rules (id TEXT PRIMARY KEY, name TEXT, directive TEXT, enabled INTEGER, paranoia_level INTEGER, category TEXT, created_at DATETIME, updated_at DATETIME)`)

	store := waf.NewStoreWithDialect(d, dialect)
	called := &atomic.Bool{}
	store.SetInvalidator(&mockWafInvalidator{called: called})

	// 2. Initial WAF config (no rules yet)
	cfg := WAFConfig{
		UseCRS:   true,
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

	// 4. Add a rule that blocks "test=1"
	err = store.AddRule(t.Context(), &waf.Rule{
		ID:        "1000",
		Name:      "Block Test 1",
		Directive: `SecRule ARGS:test "@eq 1" "id:1000,phase:2,deny,status:403"`,
		Enabled:   true,
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
