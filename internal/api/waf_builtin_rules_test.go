// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// listAllBuiltin pages through the whole list the way a client has to.
func listAllBuiltin(t *testing.T, s *ApiService, req *gateonv1.ListBuiltinWafRulesRequest) []*gateonv1.BuiltinWafRule {
	t.Helper()
	var out []*gateonv1.BuiltinWafRule
	for {
		req.Offset = int32(len(out))
		res, err := s.ListBuiltinWafRules(context.Background(), req)
		if err != nil {
			t.Fatalf("ListBuiltinWafRules: %v", err)
		}
		out = append(out, res.GetRules()...)
		if len(res.GetRules()) == 0 || len(out) >= int(res.GetTotal()) {
			return out
		}
	}
}

// TestBuiltinRulesListIsTheTableTheEngineLoads: the Rules page listed only the
// rules an operator had written, so a fresh install showed "No rules found"
// while a hundred were refusing requests. The list is asserted against the
// catalog the engine is built from, rule by rule, so it cannot drift into a
// description of something else.
func TestBuiltinRulesListIsTheTableTheEngineLoads(t *testing.T) {
	t.Parallel()

	catalog := waf.RuleCatalog()
	got := listAllBuiltin(t, &ApiService{}, &gateonv1.ListBuiltinWafRulesRequest{Limit: 7})
	if len(got) != len(catalog) {
		t.Fatalf("listed %d rules, the engine loads %d", len(got), len(catalog))
	}
	byID := make(map[uint32]*gateonv1.BuiltinWafRule, len(got))
	for i, r := range got {
		if i > 0 && got[i-1].GetId() >= r.GetId() {
			t.Fatalf("rules are not in ID order at %d, so paging can repeat or skip one", r.GetId())
		}
		byID[r.GetId()] = r
	}
	for _, want := range catalog {
		r, ok := byID[want.ID]
		if !ok {
			t.Errorf("rule %d is loaded and not listed", want.ID)
			continue
		}
		if r.GetName() != want.Msg || r.GetCategory() != want.Category || int(r.GetParanoiaLevel()) != want.ParanoiaLevel {
			t.Errorf("rule %d listed as %q/%s/PL%d, loaded as %q/%s/PL%d", want.ID,
				r.GetName(), r.GetCategory(), r.GetParanoiaLevel(), want.Msg, want.Category, want.ParanoiaLevel)
		}
		if r.GetSeverity() == "invalid" || r.GetConfidence() == "invalid" || r.GetPhase() == "invalid" {
			t.Errorf("rule %d has a field the page would print as \"invalid\": %v", want.ID, r)
		}
	}
}

// TestBuiltinRulesSayWhereDetectionComesFromAndWhatAMatchDoes pins the two
// columns an operator cannot work out from a name: whether the rule is gwaf's,
// and whether a match refuses the request or only records it.
func TestBuiltinRulesSayWhereDetectionComesFromAndWhatAMatchDoes(t *testing.T) {
	t.Parallel()

	byID := make(map[uint32]*gateonv1.BuiltinWafRule)
	for _, r := range listAllBuiltin(t, &ApiService{}, &gateonv1.ListBuiltinWafRulesRequest{}) {
		byID[r.GetId()] = r
	}
	for _, tc := range []struct {
		id             uint32
		source, action string
	}{
		{1151006, "gwaf", "block"},   // Text4Shell: gwaf's detection, refuses
		{1131001, "gwaf", "log"},     // inbound AWS key: gwaf's detection, records only
		{1210001, "gateon", "block"}, // gambling keywords: site policy, written here
	} {
		r := byID[tc.id]
		if r == nil {
			t.Fatalf("rule %d is not listed", tc.id)
		}
		if r.GetSource() != tc.source || r.GetAction() != tc.action {
			t.Errorf("rule %d: source %q action %q, want %q %q", tc.id, r.GetSource(), r.GetAction(), tc.source, tc.action)
		}
		if (r.GetSourceRuleId() != 0) != (tc.source == "gwaf") {
			t.Errorf("rule %d: source %q with gwaf rule ID %d", tc.id, r.GetSource(), r.GetSourceRuleId())
		}
	}
}

func TestBuiltinRulesFilterAndPageSizeAreBounded(t *testing.T) {
	t.Parallel()
	s := &ApiService{}

	res, err := s.ListBuiltinWafRules(context.Background(), &gateonv1.ListBuiltinWafRulesRequest{Limit: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetRules()) > maxBuiltinRulePage {
		t.Errorf("one page returned %d rules, the ceiling is %d", len(res.GetRules()), maxBuiltinRulePage)
	}
	if len(res.GetCategories()) < 5 {
		t.Errorf("categories = %v; the filter would offer almost nothing", res.GetCategories())
	}

	dlp := listAllBuiltin(t, s, &gateonv1.ListBuiltinWafRulesRequest{Category: waf.CategoryDLP})
	if len(dlp) == 0 || len(dlp) == int(res.GetTotal()) {
		t.Fatalf("category filter returned %d of %d rules", len(dlp), res.GetTotal())
	}
	for _, r := range dlp {
		if r.GetCategory() != waf.CategoryDLP {
			t.Errorf("category filter %q returned rule %d in %q", waf.CategoryDLP, r.GetId(), r.GetCategory())
		}
	}

	for _, q := range []string{"TEXT4SHELL", "1151006", "cve-2022-42889"} {
		hits := listAllBuiltin(t, s, &gateonv1.ListBuiltinWafRulesRequest{Search: q})
		if len(hits) != 1 || hits[0].GetId() != 1151006 {
			t.Errorf("search %q returned %d rules, want only 1151006", q, len(hits))
		}
	}

	past, err := s.ListBuiltinWafRules(context.Background(), &gateonv1.ListBuiltinWafRulesRequest{Offset: 1 << 20})
	if err != nil || len(past.GetRules()) != 0 || past.GetTotal() != res.GetTotal() {
		t.Errorf("an offset past the end: %d rules, total %d, err %v", len(past.GetRules()), past.GetTotal(), err)
	}
}

// TestConnectServesBuiltinRules: ConnectHandler embeds the generated
// unimplemented handler, so an RPC it does not forward compiles and answers
// "unimplemented" on that transport alone.
func TestConnectServesBuiltinRules(t *testing.T) {
	t.Parallel()

	h := NewConnectHandler(&ApiService{})
	res, err := h.ListBuiltinWafRules(context.Background(), connect.NewRequest(&gateonv1.ListBuiltinWafRulesRequest{Limit: 3}))
	if err != nil {
		t.Fatalf("Connect ListBuiltinWafRules: %v", err)
	}
	if len(res.Msg.GetRules()) != 3 || int(res.Msg.GetTotal()) != len(waf.RuleCatalog()) {
		t.Errorf("Connect returned %d rules, total %d", len(res.Msg.GetRules()), res.Msg.GetTotal())
	}
}
