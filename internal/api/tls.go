// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListTLSOptions(ctx context.Context, _ *gateonv1.ListTLSOptionsRequest) (*gateonv1.ListTLSOptionsResponse, error) {
	if s.TLSOptions == nil {
		return &gateonv1.ListTLSOptionsResponse{TlsOptions: nil}, nil
	}
	return &gateonv1.ListTLSOptionsResponse{TlsOptions: s.TLSOptions.List(ctx)}, nil
}

func (s *ApiService) UpdateTLSOption(ctx context.Context, req *gateonv1.UpdateTLSOptionRequest) (*gateonv1.UpdateTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.TlsOption == nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, nil
	}
	// Through the domain service, as REST saves one: it gives a new option the
	// id it arrives without, and invalidates. Written to the store directly,
	// every new option was kept under "" -- each overwriting the last, and none
	// deletable, since DeleteTLSOption refuses an empty id.
	if err := s.tlsOptionService().SaveTLSOption(ctx, req.TlsOption); err != nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, err
	}
	s.logAudit(ctx, "update", "tls_option", fmt.Sprintf("Updated TLS option %s", req.TlsOption.Id))
	return &gateonv1.UpdateTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) DeleteTLSOption(ctx context.Context, req *gateonv1.DeleteTLSOptionRequest) (*gateonv1.DeleteTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, nil
	}
	if err := s.tlsOptionService().DeleteTLSOption(ctx, req.Id); err != nil {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, err
	}
	s.logAudit(ctx, "delete", "tls_option", fmt.Sprintf("Deleted TLS option %s", req.Id))
	return &gateonv1.DeleteTLSOptionResponse{Success: true}, nil
}
