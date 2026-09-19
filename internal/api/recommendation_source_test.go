// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestApplyRecommendationFingerprintSourceIsNotBlockedAsIP: the multi-IP and
// impossible-travel detectors emit "security_threat" anomalies whose Source is
// a client fingerprint, not an address. Applying that recommendation used to
// write the fingerprint into an ipfilter deny_list, attach it to every route,
// and report the actor as blocked, while the filter matched nothing.
func TestApplyRecommendationFingerprintSourceIsNotBlockedAsIP(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	routeStore := config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json"))
	mwStore := config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json"))
	_ = routeStore.Update(ctx, &gateonv1.Route{Id: "rt1", Name: "Route1"})

	svc := NewApiService(ApiServiceConfig{Routes: routeStore, Middlewares: mwStore})

	const fp = "t13d1516h2_8daaf6152771_b0da82dd1658"
	resp, err := svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
		AnomalyType: "security_threat",
		Source:      fp,
	})
	if err != nil {
		t.Fatalf("ApplyRecommendation: %v", err)
	}
	if mws := mwStore.List(ctx); len(mws) != 0 {
		t.Fatalf("a fingerprint was written into an ipfilter: %+v", mws)
	}
	rt, _ := routeStore.Get(ctx, "rt1")
	if len(rt.Middlewares) != 0 {
		t.Fatalf("route gained middlewares for a non-IP source: %v", rt.Middlewares)
	}
	if strings.Contains(resp.Message, "blocked via middleware") {
		t.Fatalf("response claims an IP block for a fingerprint: %q", resp.Message)
	}
}
