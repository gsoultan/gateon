package api

import (
	"context"

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

	rules, total, err := s.WafRules.ListRules(ctx, limit, offset, search)
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
			Directive:     r.Directive,
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
		Directive:     req.Rule.Directive,
		Enabled:       req.Rule.Enabled,
		ParanoiaLevel: int(req.Rule.ParanoiaLevel),
		Category:      req.Rule.Category,
	}

	if err := s.WafRules.AddRule(ctx, r); err != nil {
		return &gateonv1.CreateWafRuleResponse{Success: false}, err
	}

	return &gateonv1.CreateWafRuleResponse{
		Success: true,
		Rule: &gateonv1.WafRule{
			Id:            r.ID,
			Name:          r.Name,
			Directive:     r.Directive,
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
		Directive:     req.Rule.Directive,
		Enabled:       req.Rule.Enabled,
		ParanoiaLevel: int(req.Rule.ParanoiaLevel),
		Category:      req.Rule.Category,
	}

	if err := s.WafRules.UpdateRule(ctx, r); err != nil {
		return &gateonv1.UpdateWafRuleResponse{Success: false}, err
	}

	return &gateonv1.UpdateWafRuleResponse{Success: true}, nil
}

func (s *ApiService) DeleteWafRule(ctx context.Context, req *gateonv1.DeleteWafRuleRequest) (*gateonv1.DeleteWafRuleResponse, error) {
	if s.WafRules == nil {
		return &gateonv1.DeleteWafRuleResponse{Success: false}, nil
	}

	if err := s.WafRules.DeleteRule(ctx, req.Id); err != nil {
		return &gateonv1.DeleteWafRuleResponse{Success: false}, err
	}

	return &gateonv1.DeleteWafRuleResponse{Success: true}, nil
}
