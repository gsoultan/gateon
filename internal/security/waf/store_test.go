// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package waf

import (
	"context"
	"fmt"
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
		if r.ID == "1900300" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rule 1900300 to be found")
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

func TestStore_ListRules(t *testing.T) {
	databaseURL := "sqlite::memory:"
	_ = InitStore(databaseURL)
	store := GetStore()
	ctx := context.Background()

	// Clear existing rules
	_, _ = store.db.Exec("DELETE FROM waf_rules")

	// Add 15 rules
	for i := 1; i <= 15; i++ {
		id := fmt.Sprintf("rule-%d", i)
		if i < 10 {
			id = fmt.Sprintf("rule-0%d", i) // rule-01, rule-02...
		}
		_ = store.AddRule(ctx, &Rule{
			ID:        id,
			Name:      fmt.Sprintf("Rule %d", i),
			Directive: "SecRule ...",
			Category:  "test",
			Enabled:   true,
		})
	}

	// Test Paging
	rules, total, err := store.ListRules(ctx, 10, 0, "", "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if total != 15 {
		t.Errorf("expected total 15, got %d", total)
	}
	if len(rules) != 10 {
		t.Errorf("expected 10 rules on page 1, got %d", len(rules))
	}

	rules, total, err = store.ListRules(ctx, 10, 10, "", "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if len(rules) != 5 {
		t.Errorf("expected 5 rules on page 2, got %d", len(rules))
	}

	// Test Search by ID
	rules, total, err = store.ListRules(ctx, 10, 0, "rule-05", "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1 for search 'rule-05', got %d", total)
	}
	if rules[0].ID != "rule-05" {
		t.Errorf("expected rule ID 'rule-05', got %q", rules[0].ID)
	}

	// Add a numeric ID rule
	_ = store.AddRule(ctx, &Rule{
		ID:        "920100",
		Name:      "Numeric Rule",
		Directive: "SecRule ...",
		Category:  "test",
		Enabled:   true,
	})

	// Test Search by numeric ID
	rules, total, err = store.ListRules(ctx, 10, 0, "920100", "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1 for search '920100', got %d", total)
	}
	if rules[0].ID != "920100" {
		t.Errorf("expected rule ID '920100', got %q", rules[0].ID)
	}

	// Test Search by Name
	rules, total, err = store.ListRules(ctx, 10, 0, "Rule 12", "")
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1 for search 'Rule 12', got %d", total)
	}
	if rules[0].Name != "Rule 12" {
		t.Errorf("expected rule Name 'Rule 12', got %q", rules[0].Name)
	}
}
