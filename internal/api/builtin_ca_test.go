// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/tls/builtinca"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestListBuiltinCertificateAuthorities(t *testing.T) {
	s := &ApiService{}
	all, err := s.ListBuiltinCertificateAuthorities(context.Background(), &gateonv1.ListBuiltinCertificateAuthoritiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if int(all.TotalCount) != len(builtinca.All()) || len(all.Authorities) != len(builtinca.All()) {
		t.Fatalf("got %d of %d, want every built-in CA", len(all.Authorities), all.TotalCount)
	}
	byRef := map[string]*gateonv1.BuiltinCertificateAuthority{}
	for _, a := range all.Authorities {
		byRef[a.Ref] = a
		if a.NotAfter == "" || len(a.Sha256Fingerprint) != 64 || a.Subject == "" {
			t.Errorf("%s: incomplete entry %v", a.Ref, a)
		}
	}
	if a := byRef[builtinca.Prefix+"cloudflare-origin-ca-ecc"]; a == nil || a.KeyAlgorithm != "ECDSA" ||
		a.Use != gateonv1.BuiltinCertificateAuthorityUse_BUILTIN_CERTIFICATE_AUTHORITY_USE_SERVER_CHAIN {
		t.Errorf("ECC origin CA entry wrong: %v", a)
	}
	if a := byRef[builtinca.Prefix+"cloudflare-origin-pull-ca"]; a == nil ||
		a.Use != gateonv1.BuiltinCertificateAuthorityUse_BUILTIN_CERTIFICATE_AUTHORITY_USE_CLIENT_CA {
		t.Errorf("origin pull CA entry wrong: %v", a)
	}

	page, err := s.ListBuiltinCertificateAuthorities(context.Background(), &gateonv1.ListBuiltinCertificateAuthoritiesRequest{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Authorities) != 1 || page.Authorities[0].Ref != all.Authorities[2].Ref {
		t.Fatalf("page 1 of size 2 = %v, want the third entry", page.Authorities)
	}
	past, err := s.ListBuiltinCertificateAuthorities(context.Background(), &gateonv1.ListBuiltinCertificateAuthoritiesRequest{Page: MaxListPage, PageSize: MaxListPageSize})
	if err != nil || len(past.Authorities) != 0 {
		t.Fatalf("page past the end = %v, %v; want empty", past.Authorities, err)
	}
}

// The list flags expiry from the certificate itself, so a stale built-in CA is
// visible in the dashboard before it breaks a handshake.
func TestBuiltinCertificateAuthoritiesFlagExpiry(t *testing.T) {
	a, _ := builtinca.Lookup(builtinca.Prefix + "cloudflare-origin-ca-rsa")
	cert, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	find := func(now time.Time) *gateonv1.BuiltinCertificateAuthority {
		list, err := BuiltinCertificateAuthorities(now)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range list {
			if e.Ref == a.Ref {
				return e
			}
		}
		t.Fatal("rsa entry missing")
		return nil
	}
	if e := find(cert.NotAfter.AddDate(-1, 0, 0)); e.Expired || e.ExpiringSoon {
		t.Errorf("a year out: %v", e)
	}
	if e := find(cert.NotAfter.AddDate(0, 0, -10)); e.Expired || !e.ExpiringSoon {
		t.Errorf("ten days out: %v", e)
	}
	if e := find(cert.NotAfter.Add(time.Hour)); !e.Expired || !e.ExpiringSoon {
		t.Errorf("after expiry: %v", e)
	}
}
