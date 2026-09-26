// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// validatingTLS answers every certificate check the same way, which is all
// GET /v1/global asks of the TLS manager.
type validatingTLS struct {
	gtls.TLSManager
}

func (validatingTLS) ValidateCertificateFiles(_, _, _ string) (*gateonv1.CertificateValidation, error) {
	return &gateonv1.CertificateValidation{Valid: true, Warnings: []string{"stamped by a read"}}, nil
}

type certGlobalsAPI struct {
	globalsAPI
}

func (*certGlobalsAPI) GetTLSManager() gtls.TLSManager { return validatingTLS{} }

// TestGlobalConfigReadLeavesTheLiveConfigAlone: GET /v1/global stamped each
// certificate's validation onto the registry's own config, because Get hands
// out its stored pointer. Every read was an unsynchronised write to state the
// rest of the gateway reads concurrently, and the next save persisted into
// global.json a validation computed for one response.
func TestGlobalConfigReadLeavesTheLiveConfigAlone(t *testing.T) {
	ctx := context.Background()
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	if err := reg.Update(ctx, &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{
		Certificates: []*gateonv1.Certificate{{Id: "c1", CertFile: "cert.pem", KeyFile: "key.pem"}},
	}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &certGlobalsAPI{globalsAPI{store: reg}}, &Deps{})

	for _, role := range []string{auth.RoleAdmin, auth.RoleViewer} {
		rr := getGlobalAs(t, mux, role)
		if !strings.Contains(rr.Body.String(), "stamped by a read") {
			t.Fatalf("GET /v1/global as %s did not report the certificate's validation: %s", role, rr.Body)
		}
		if v := reg.Get(ctx).GetTls().GetCertificates()[0].GetValidation(); v != nil {
			t.Fatalf("GET /v1/global as %s wrote a validation into the live config: %v", role, v)
		}
	}
}
