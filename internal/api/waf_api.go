// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListWafRules(ctx context.Context, req *gateonv1.ListWafRulesRequest) (*gateonv1.ListWafRulesResponse, error) {
	if s.WafRules == nil {
		return &gateonv1.ListWafRulesResponse{}, nil
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	offset := int(req.GetOffset())
	search := req.GetSearch()
	category := req.GetCategory()

	rules, total, err := s.WafRules.ListRules(ctx, limit, offset, search, category)
	if err != nil {
		return nil, err
	}

	resp := &gateonv1.ListWafRulesResponse{
		Total: int32(total),
	}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, &gateonv1.WafRule{
			Id:            r.ID,
			Name:          r.Name,
			Directive:     ruleBody(&r),
			Enabled:       r.Enabled,
			ParanoiaLevel: int32(r.ParanoiaLevel),
			Category:      r.Category,
			CreatedAt:     r.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:     r.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return resp, nil
}

func (s *ApiService) CreateWafRule(ctx context.Context, req *gateonv1.CreateWafRuleRequest) (*gateonv1.CreateWafRuleResponse, error) {
	if s.WafRules == nil || req.Rule == nil {
		return &gateonv1.CreateWafRuleResponse{Success: false}, nil
	}

	r := &waf.Rule{
		ID:            req.Rule.Id,
		Name:          req.Rule.Name,
		Enabled:       req.Rule.Enabled,
		ParanoiaLevel: int(req.Rule.ParanoiaLevel),
		Category:      req.Rule.Category,
	}
	if err := ruleBodyToRule(req.Rule.Directive, r); err != nil {
		return &gateonv1.CreateWafRuleResponse{Success: false}, err
	}

	if err := s.WafRules.AddRule(ctx, r); err != nil {
		return &gateonv1.CreateWafRuleResponse{Success: false}, err
	}

	s.logAudit(ctx, "create", "waf_rule", fmt.Sprintf("Created WAF rule: %s", r.ID))

	return &gateonv1.CreateWafRuleResponse{
		Success: true,
		Rule: &gateonv1.WafRule{
			Id:            r.ID,
			Name:          r.Name,
			Directive:     ruleBody(r),
			Enabled:       r.Enabled,
			ParanoiaLevel: int32(r.ParanoiaLevel),
			Category:      r.Category,
			CreatedAt:     r.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt:     r.UpdatedAt.Format("2006-01-02 15:04:05"),
		},
	}, nil
}

func (s *ApiService) UpdateWafRule(ctx context.Context, req *gateonv1.UpdateWafRuleRequest) (*gateonv1.UpdateWafRuleResponse, error) {
	if s.WafRules == nil || req.Rule == nil {
		return &gateonv1.UpdateWafRuleResponse{Success: false}, nil
	}

	r := &waf.Rule{
		ID:            req.Rule.Id,
		Name:          req.Rule.Name,
		Enabled:       req.Rule.Enabled,
		ParanoiaLevel: int(req.Rule.ParanoiaLevel),
		Category:      req.Rule.Category,
	}
	if err := ruleBodyToRule(req.Rule.Directive, r); err != nil {
		return &gateonv1.UpdateWafRuleResponse{Success: false}, err
	}

	if err := s.WafRules.UpdateRule(ctx, r); err != nil {
		return &gateonv1.UpdateWafRuleResponse{Success: false}, err
	}

	s.logAudit(ctx, "update", "waf_rule", fmt.Sprintf("Updated WAF rule: %s", r.ID))

	return &gateonv1.UpdateWafRuleResponse{Success: true}, nil
}

func (s *ApiService) DeleteWafRule(ctx context.Context, req *gateonv1.DeleteWafRuleRequest) (*gateonv1.DeleteWafRuleResponse, error) {
	if s.WafRules == nil {
		return &gateonv1.DeleteWafRuleResponse{Success: false}, nil
	}

	if err := s.WafRules.DeleteRule(ctx, req.Id); err != nil {
		return &gateonv1.DeleteWafRuleResponse{Success: false}, err
	}

	s.logAudit(ctx, "delete", "waf_rule", fmt.Sprintf("Deleted WAF rule: %s", req.Id))

	return &gateonv1.DeleteWafRuleResponse{Success: true}, nil
}

// ruleBodyToRule fills in the stored form of a rule from the request's rule
// body.
//
// The wire field is still called "directive" because it is the same free-text
// rule body it always was; what changed is the language written in it. A typed
// definition is stored and enforced. Anything else is refused at the point of
// authoring with a message saying so, rather than stored and quietly never
// run — an operator who saves a rule and is told it worked will believe they
// are protected.
func ruleBodyToRule(body string, r *waf.Rule) error {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return fmt.Errorf("a rule needs a definition")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return fmt.Errorf(
			"this looks like a SecLang directive. The WAF engine no longer parses " +
				"SecLang; rules are now written as a JSON definition, for example: " +
				`{"phase":"request_body","targets":["args"],` +
				`"operator":{"kind":"contains","pattern":"evil"},` +
				`"severity":"critical","confidence":"high","msg":"Evil detected"}`)
	}
	def, err := waf.ParseDefinition(trimmed)
	if err != nil {
		return err
	}
	if err := def.Validate(); err != nil {
		return err
	}
	r.Definition = trimmed
	r.Format = waf.FormatGateon
	return nil
}

// ruleBody is what the dashboard shows and edits: the typed definition when
// there is one, and otherwise the original SecLang so an operator converting a
// legacy rule can still see what it used to say.
func ruleBody(r *waf.Rule) string {
	if r.Definition != "" {
		return r.Definition
	}
	return r.Directive
}
