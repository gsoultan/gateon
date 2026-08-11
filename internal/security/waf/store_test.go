// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"fmt"
	"testing"
)

// TestStore_DoesNotSeedDefaultRules pins the inversion of what this test used
// to assert. gateon's default rules were 75 SecLang rows seeded into every
// install; they are now compiled into the binary, so a fresh database must come
// up with none of them.
//
// It matters that Seed is exercised rather than skipped: a Seed that quietly
// reinserted the defaults would undo migration 60 on the next restart, and the
// only visible symptom would be 75 unenforceable SecLang rows reappearing.
func TestStore_DoesNotSeedDefaultRules(t *testing.T) {
	databaseURL := "sqlite::memory:"

	if err := InitStore(databaseURL); err != nil {
		t.Fatalf("InitStore failed: %v", err)
	}

	store := GetStore()
	if store == nil {
		t.Fatal("GetStore returned nil")
	}

	if err := store.Seed(context.Background()); err != nil {
		t.Fatalf("Seed failed: %v", err)
	}

	for _, r := range store.GetAllRules() {
		if _, seeded := RetirementByID(r.ID); seeded {
			t.Errorf("retired default rule %s (%s) is present in the database", r.ID, r.Name)
		}
		for _, s := range defaultSpecs {
			if r.ID == fmt.Sprint(s.id) {
				t.Errorf("built-in rule %d is also stored in the database; it would "+
					"be compiled twice and collide on ID", s.id)
			}
		}
	}
}

// TestStore_CompiledRulesRejectsUnconvertedRules covers the state an install
// lands in immediately after the engine migration: rows that are still SecLang.
//
// They must not be silently skipped. A skipped rule and an enforced rule look
// identical from the dashboard, so an operator would believe a protection is
// running when nothing can execute it.
func TestStore_CompiledRulesRejectsUnconvertedRules(t *testing.T) {
	databaseURL := "sqlite::memory:"
	_ = InitStore(databaseURL)
	store := GetStore()
	ctx := context.Background()
	_, _ = store.db.Exec("DELETE FROM waf_rules")

	legacy := &Rule{
		ID:            "2000001",
		Name:          "Legacy SecLang rule",
		Directive:     `SecRule ARGS "@rx evil" "id:2000001,phase:2,deny"`,
		Format:        FormatSecLang,
		Enabled:       true,
		ParanoiaLevel: 1,
		Category:      "Test",
	}
	if err := store.AddRule(ctx, legacy); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	typed := &Rule{
		ID:   "2000002",
		Name: "Typed rule",
		Definition: `{"phase":"request_body","targets":["args"],
			"transforms":["urldecode","lowercase"],
			"operator":{"kind":"contains","pattern":"evil"},
			"severity":"critical","confidence":"high","msg":"Evil detected",
			"tags":["test"]}`,
		Format:        FormatGateon,
		Enabled:       true,
		ParanoiaLevel: 1,
		Category:      "Test",
	}
	if err := store.AddRule(ctx, typed); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	set, problems := store.CompiledRules(1)
	if len(set) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(set))
	}
	if set[0].ID != 2000002 {
		t.Errorf("compiled rule %d, want 2000002", set[0].ID)
	}
	if len(problems) != 1 {
		t.Fatalf("reported %d problems, want 1", len(problems))
	}
	if problems[0].ID != "2000001" {
		t.Errorf("reported rule %s, want 2000001", problems[0].ID)
	}
}

// TestStore_CompiledRulesRespectsParanoiaLevel keeps the stored level meaning
// what it did under Coraza, where the directive builder filtered on it.
func TestStore_CompiledRulesRespectsParanoiaLevel(t *testing.T) {
	databaseURL := "sqlite::memory:"
	_ = InitStore(databaseURL)
	store := GetStore()
	ctx := context.Background()
	_, _ = store.db.Exec("DELETE FROM waf_rules")

	def := `{"phase":"request_body","targets":["args"],
		"operator":{"kind":"contains","pattern":"noisy"},
		"severity":"warning","confidence":"medium","msg":"Noisy heuristic",
		"tags":["test"]}`

	if err := store.AddRule(ctx, &Rule{
		ID: "2000003", Name: "PL2 rule", Definition: def, Format: FormatGateon,
		Enabled: true, ParanoiaLevel: 2, Category: "Test",
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if set, _ := store.CompiledRules(1); len(set) != 0 {
		t.Errorf("a PL2 rule compiled at PL1: %d rules", len(set))
	}
	if set, problems := store.CompiledRules(2); len(set) != 1 || len(problems) != 0 {
		t.Errorf("at PL2 got %d rules and %d problems, want 1 and 0", len(set), len(problems))
	}
}

// TestStore_HashedRuleIDsAreStable guards the identifier a dashboard-authored
// rule gets. gwaf identifies a rule by a number that appears in every decision,
// audit record and exception, so a UUID-backed rule whose number changed
// between restarts would silently repoint every exception written against it.
func TestStore_HashedRuleIDsAreStable(t *testing.T) {
	t.Parallel()

	const uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	first := hashedRuleID(uuid)
	if first != hashedRuleID(uuid) {
		t.Error("hashedRuleID is not deterministic")
	}
	if first < userRuleIDMin {
		t.Errorf("hashedRuleID produced %d, inside the engine's reserved range", first)
	}
	if hashedRuleID(uuid) == hashedRuleID("a-different-rule") {
		t.Error("two distinct rule identifiers collided")
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
	// The total is the size of the whole result set, not of the page, so it
	// must not change as the caller walks pages — a dashboard paginator that
	// re-reads it per page would otherwise jump around.
	if total != 15 {
		t.Errorf("expected total 15 on page 2, got %d", total)
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
