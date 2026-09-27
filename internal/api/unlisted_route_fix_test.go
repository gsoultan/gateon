// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// The Security Hub's "Apply automatic fix" on an unlisted_route anomaly was
// answered with success -- the dashboard showed "Recommendation applied" and
// "Route for '<source>' has been flagged. Please complete the registration in
// the Routes panel." -- and the audit log recorded "Applied resolution", but
// applyCreateRouteRecommendation changed nothing: no route, no middleware, no
// global setting, nothing a Routes panel could show. The source it named as a
// route was the client's IP: UnlistedRouteDetector sets Anomaly.Source to
// tr.SourceIP, and the dashboard sent anomaly.source.
//
// Decided: the fix creates a paused route for the finding's path (the tests
// below). A request that carries only what the dashboard used to send -- no
// path -- has nothing to route and must say so. What this test rejects is
// reporting a no-op as applied.
func TestApplyRecommendationUnlistedRouteSucceedsOnlyIfItChangedSomething(t *testing.T) {
	ctx := t.Context()
	stores := newFixStores(t)
	svc := NewApiService(ApiServiceConfig{
		EntryPoints: config.NewEntryPointRegistry(filepath.Join(t.TempDir(), "entrypoints.json")),
		Routes:      stores.routes,
		Services:    config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json")),
		Middlewares: stores.mws,
		Globals:     stores.globals,
	})

	before := stores.snapshot(ctx, t)
	// Exactly what AnomalyEngineTab sends: applyRecommendation(anomaly.type,
	// anomaly.source, anomaly.id), where source is the requesting client's IP.
	resp, err := svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{
		AnomalyType: "unlisted_route",
		Source:      "203.0.113.11",
		ThreatId:    "t-1",
	})
	if err != nil {
		t.Fatalf("ApplyRecommendation: %v", err)
	}
	after := stores.snapshot(ctx, t)

	if resp.GetSuccess() && bytes.Equal(before, after) {
		t.Fatalf("reported success but changed no route, middleware or global setting; message: %q",
			resp.GetMessage())
	}
	if resp.GetSuccess() && strings.Contains(resp.GetMessage(), "Route for '203.0.113.11'") {
		t.Errorf("the message names the client's IP as a route: %q", resp.GetMessage())
	}
}

// fixStores are the configuration an applied recommendation can change.
type fixStores struct {
	routes  *config.RouteRegistry
	mws     *config.MiddlewareRegistry
	globals *config.GlobalRegistry
}

func newFixStores(t *testing.T) fixStores {
	t.Helper()
	dir := t.TempDir()
	s := fixStores{
		routes:  config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		mws:     config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json")),
	}
	route := &gateonv1.Route{Id: "rt1", Name: "Route1", Rule: "PathPrefix(`/app`)"}
	if err := s.routes.Update(t.Context(), route); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return s
}

// snapshot serialises every route, middleware and the global config in a
// stable order, so two snapshots are equal exactly when nothing changed.
func (s fixStores) snapshot(ctx context.Context, t *testing.T) []byte {
	t.Helper()
	msgs := make([]proto.Message, 0, 8)
	routes := s.routes.List(ctx)
	slices.SortFunc(routes, func(a, b *gateonv1.Route) int { return strings.Compare(a.GetId(), b.GetId()) })
	for _, r := range routes {
		msgs = append(msgs, r)
	}
	mws := s.mws.List(ctx)
	slices.SortFunc(mws, func(a, b *gateonv1.Middleware) int { return strings.Compare(a.GetId(), b.GetId()) })
	for _, m := range mws {
		msgs = append(msgs, m)
	}
	msgs = append(msgs, s.globals.Get(ctx))

	var out bytes.Buffer
	for _, m := range msgs {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatalf("marshal %T: %v", m, err)
		}
		out.Write(b)
		out.WriteByte(0)
	}
	return out.Bytes()
}
