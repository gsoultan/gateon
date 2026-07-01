package waf

import (
	"context"
	"testing"
)

func TestStore_SeedAndReload(t *testing.T) {
	// Use in-memory SQLite for testing
	databaseURL := "sqlite::memory:"

	err := InitStore(databaseURL)
	if err != nil {
		t.Fatalf("InitStore failed: %v", err)
	}

	store := GetStore()
	if store == nil {
		t.Fatal("GetStore returned nil")
	}

	rules := store.GetAllRules()
	if len(rules) == 0 {
		t.Error("expected rules to be seeded, got 0")
	}

	// Verify some specific rule
	found := false
	for _, r := range rules {
		if r.ID == "900300" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rule 900300 to be found")
	}
}

func TestStore_AddUpdateDelete(t *testing.T) {
	databaseURL := "sqlite::memory:"
	_ = InitStore(databaseURL)
	store := GetStore()

	ctx := context.Background()
	rule := &Rule{
		ID:            "test-rule",
		Name:          "Test Rule",
		Directive:     "SecRule ARGS:test \"@eq 1\" \"id:test-rule,phase:1,deny\"",
		Enabled:       true,
		ParanoiaLevel: 1,
		Category:      "Test",
	}

	if err := store.AddRule(ctx, rule); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Verify added
	rules := store.GetAllRules()
	found := false
	for _, r := range rules {
		if r.ID == "test-rule" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("rule not found after AddRule")
	}

	// Update
	rule.Name = "Updated Name"
	if err := store.UpdateRule(ctx, rule); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	// Verify updated
	rules = store.GetAllRules()
	for _, r := range rules {
		if r.ID == "test-rule" {
			if r.Name != "Updated Name" {
				t.Errorf("expected name 'Updated Name', got %q", r.Name)
			}
		}
	}

	// Delete
	if err := store.DeleteRule(ctx, "test-rule"); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Verify deleted
	rules = store.GetAllRules()
	for _, r := range rules {
		if r.ID == "test-rule" {
			t.Fatal("rule still found after DeleteRule")
		}
	}
}
