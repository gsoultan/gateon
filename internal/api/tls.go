// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/tls/builtinca"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) ListTLSOptions(ctx context.Context, req *gateonv1.ListTLSOptionsRequest) (*gateonv1.ListTLSOptionsResponse, error) {
	if s.TLSOptions == nil {
		return &gateonv1.ListTLSOptionsResponse{TlsOptions: nil}, nil
	}
	page, size := listPage(req.GetPage(), req.GetPageSize())
	opts, total := s.TLSOptions.ListPaginated(ctx, page, size, req.GetSearch())
	return &gateonv1.ListTLSOptionsResponse{TlsOptions: opts, TotalCount: total, Page: page, PageSize: size}, nil
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

// builtinCAExpiryWindow matches the window the certificate validation warns
// in, so the list and a certificate using the CA agree on "expiring soon".
const builtinCAExpiryWindow = 90 * 24 * time.Hour

// ListBuiltinCertificateAuthorities lists the CA certificates compiled into
// the binary, with the expiry and fingerprint of each, so a stale one is seen
// in the dashboard rather than in a failed handshake.
func (s *ApiService) ListBuiltinCertificateAuthorities(_ context.Context, req *gateonv1.ListBuiltinCertificateAuthoritiesRequest) (*gateonv1.ListBuiltinCertificateAuthoritiesResponse, error) {
	all, err := BuiltinCertificateAuthorities(time.Now())
	if err != nil {
		return nil, err
	}
	page, size := listPage(req.GetPage(), req.GetPageSize())
	total := int32(len(all)) // #nosec G115 -- a fixed catalog of a handful of entries.
	if size == 0 {           // unset: everything, as the stores answer it
		return &gateonv1.ListBuiltinCertificateAuthoritiesResponse{Authorities: all, TotalCount: total, Page: page}, nil
	}
	start := min(int64(page)*int64(size), int64(total))
	end := min(start+int64(size), int64(total))
	return &gateonv1.ListBuiltinCertificateAuthoritiesResponse{
		Authorities: all[start:end], TotalCount: total, Page: page, PageSize: size,
	}, nil
}

// BuiltinCertificateAuthorities describes every built-in CA as of now. An
// embedded certificate that fails its pinned fingerprint is an error, not an
// entry: the catalog is either exactly what was published or it is refused.
func BuiltinCertificateAuthorities(now time.Time) ([]*gateonv1.BuiltinCertificateAuthority, error) {
	authorities := builtinca.All()
	out := make([]*gateonv1.BuiltinCertificateAuthority, 0, len(authorities))
	for _, a := range authorities {
		cert, err := a.Certificate()
		if err != nil {
			return nil, err
		}
		out = append(out, &gateonv1.BuiltinCertificateAuthority{
			Ref:               a.Ref,
			Name:              a.Name,
			Use:               builtinCAUse(a.Use),
			KeyAlgorithm:      cert.PublicKeyAlgorithm.String(),
			Subject:           cert.Subject.String(),
			NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
			Sha256Fingerprint: a.SHA256,
			Expired:           now.After(cert.NotAfter),
			ExpiringSoon:      cert.NotAfter.Sub(now) < builtinCAExpiryWindow,
		})
	}
	return out, nil
}

func builtinCAUse(u builtinca.Use) gateonv1.BuiltinCertificateAuthorityUse {
	switch u {
	case builtinca.UseServerChain:
		return gateonv1.BuiltinCertificateAuthorityUse_BUILTIN_CERTIFICATE_AUTHORITY_USE_SERVER_CHAIN
	case builtinca.UseClientCA:
		return gateonv1.BuiltinCertificateAuthorityUse_BUILTIN_CERTIFICATE_AUTHORITY_USE_CLIENT_CA
	default:
		return gateonv1.BuiltinCertificateAuthorityUse_BUILTIN_CERTIFICATE_AUTHORITY_USE_UNSPECIFIED
	}
}
