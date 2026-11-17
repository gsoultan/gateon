// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auditrecord_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func adminCtx(t *testing.T) (context.Context, string) {
	t.Helper()
	id := "admin-" + uniqueID(t)
	return context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: id, Username: "admin", Role: auth.RoleAdmin}), id
}

func entriesFor(t *testing.T, id, resource string) []string {
	t.Helper()
	var out []string
	for _, e := range entriesBy(t, id) {
		if e.Resource == resource {
			out = append(out, e.Details)
		}
	}
	return out
}

// Switching the gateway-wide WAF off, or to audit-only, was recorded as
// "Updated global configuration" and nothing more, which no alert could tell
// from a change of log level (ADR 0099).
func TestSwitchingTheWAFDownNamesItInTheAuditLog(t *testing.T) {
	svc, conf := serviceWithAuditOn(t)
	conf.Waf = &gateonv1.WafConfig{Enabled: true, ParanoiaLevel: 2}
	ctx, id := adminCtx(t)
	if _, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
		t.Fatal(err)
	}
	next := proto.CloneOf(conf)
	next.Waf.Enabled = false
	next.Waf.AuditOnly = true
	if _, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: next}); err != nil {
		t.Fatal(err)
	}
	got := entriesFor(t, id, "waf_config")
	if len(got) != 2 {
		t.Fatalf("got %d WAF entries, want 2 (switched on, then down): %q", len(got), got)
	}
	if !strings.Contains(got[0], "enabled true -> false") || !strings.Contains(got[0], "audit only false -> true") {
		t.Fatalf("newest WAF entry = %q, want it to name the switch-off and audit-only", got[0])
	}
}

// A save that leaves the WAF and alerting as they were says nothing about
// them: an entry on every save would be an alert on every save.
func TestAnUnrelatedSaveWritesNoProtectionEntry(t *testing.T) {
	svc, conf := serviceWithAuditOn(t)
	ctx, id := adminCtx(t)
	conf.Log = &gateonv1.LogConfig{Level: "debug"}
	if _, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
		t.Fatal(err)
	}
	if got := append(entriesFor(t, id, "waf_config"), entriesFor(t, id, "alerting_config")...); len(got) != 0 {
		t.Fatalf("an unrelated save wrote protection entries: %q", got)
	}
}

func TestChangingAlertingIsAudited(t *testing.T) {
	svc, conf := serviceWithAuditOn(t)
	ctx, id := adminCtx(t)
	conf.Alerting = &gateonv1.AlertingConfig{Enabled: true}
	if _, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
		t.Fatal(err)
	}
	if got := entriesFor(t, id, "alerting_config"); len(got) != 1 || !strings.Contains(got[0], "enabled true") {
		t.Fatalf("alerting entries = %q, want one naming the change", got)
	}
}
