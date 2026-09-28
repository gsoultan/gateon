// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/config/storedsecret"
	wafmw "github.com/gsoultan/gateon/internal/middleware/security/waf"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) GetGlobalConfig(ctx context.Context, _ *gateonv1.GetGlobalConfigRequest) (*gateonv1.GetGlobalConfigResponse, error) {
	if s.Globals == nil {
		return &gateonv1.GetGlobalConfigResponse{Config: &gateonv1.GlobalConfig{}}, nil
	}
	conf := GlobalConfigView(s.Globals, s.Globals.Get(ctx), callerMayWrite(ctx, auth.ResourceGlobal))
	return &gateonv1.GetGlobalConfigResponse{Config: conf}, nil
}

// GlobalConfigView is gc as the management API hands it to a caller, over
// every transport: GET /v1/global and GetGlobalConfig over Connect and gRPC.
//
// No caller receives a stored credential. One who may write the configuration
// reads each as storedsecret.Sentinel -- or as its reference, when it was
// configured as one, so that saving stores the reference back -- and sends the
// sentinel back to keep it; one who may not reads "". Writers used to receive
// every value: the PASETO key that signs sessions, the audit chain's HMAC key,
// the database and Redis passwords and every third-party token. One stolen
// administrator session or one script in the dashboard was then a key to
// mint sessions for any account, which outlived the session, the password
// and a sign-out. See ADR 0028.
//
// gc is never modified; the registry hands out its live config.
func GlobalConfigView(store config.GlobalConfigStore, gc *gateonv1.GlobalConfig, mayWrite bool) *gateonv1.GlobalConfig {
	if gc == nil {
		return nil
	}
	if !mayWrite {
		return RedactGlobalSecrets(gc)
	}
	out := cloneGlobalConfig(config.WithSecretReferences(store, gc))
	storedsecret.Mask(out)
	return out
}

func cloneGlobalConfig(gc *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	out, ok := proto.Clone(gc).(*gateonv1.GlobalConfig)
	if !ok || out == nil {
		return &gateonv1.GlobalConfig{}
	}
	return out
}

// callerMayWrite reports whether the caller in ctx holds ActionWrite on
// resource. No claims value at all means PasetoAuth never ran, i.e. auth is
// disabled, which every other check on this service and handlers.RequirePermission
// treat as permitted. A claims value that cannot be read establishes nothing
// and is treated as no permission -- never as "there is nobody to check".
func callerMayWrite(ctx context.Context, resource auth.Resource) bool {
	claims, present := callerClaims(ctx)
	if !present {
		return true
	}
	if claims == nil {
		return false
	}
	return auth.Allowed(ctx, claims.Role, auth.ActionWrite, resource)
}

// RedactGlobalSecrets returns a copy of gc with every credential blanked: what
// a caller who may not write the global configuration reads.
//
// The viewer role -- read-only by definition -- holds ActionRead on
// ResourceGlobal so the dashboard can render settings, and that read used to
// return the PASETO session key, the audit chain's HMAC signing key, the
// database and Redis passwords and every third-party API token verbatim. The
// fields are storedsecret's table, the one the writer's view masks and a save
// restores, so the three cannot disagree about what a credential is.
//
// The copy is what makes this safe on the live config: the registry hands
// out its stored pointer, and blanking fields on that would erase the secrets
// from the running gateway.
func RedactGlobalSecrets(gc *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	if gc == nil {
		return nil
	}
	out := cloneGlobalConfig(gc)
	storedsecret.Blank(out)
	return out
}

// KeepOmittedSections gives every top-level section an update leaves out the
// value already stored, so an update changes what it carries and nothing else.
//
// Both transports used to store the request as the whole configuration. A body
// carrying one section -- `{"waf": {...}}`, which is what doc/waf-origins.md
// shows, and what the certificate pages send when their initial read failed --
// therefore deleted every other one: the auth block with its database settings
// and session key, the management allowlist, every certificate. Nothing failed
// at the time. On the next start the bootstrap found no auth database, pointed
// auth at a fresh local SQLite file with no administrator -- reopening Setup,
// which is served before authentication -- and the management plane came back
// on its default of every interface and every address.
//
// Absence is only readable for message fields, which proto3 tracks, and every
// top-level field is one except profile, whose empty value is not a choice the
// dashboard can make (it always sends a named tier). A section that is present
// replaces the stored one outright, empty or not: this merges sections, not the
// fields inside them. Carried sections are clones, because the registry keeps
// the previous config for its change listeners and the update becomes the live
// one; sharing a message between them would let a write to either reach both.
func KeepOmittedSections(update, stored *gateonv1.GlobalConfig) {
	if update == nil || stored == nil {
		return
	}
	u, s := update.ProtoReflect(), stored.ProtoReflect()
	fields := u.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.Message() == nil || fd.IsList() || fd.IsMap() || u.Has(fd) || !s.Has(fd) {
			continue
		}
		u.Set(fd, protoreflect.ValueOfMessage(proto.Clone(s.Get(fd).Message().Interface()).ProtoReflect()))
	}
	if update.Profile == "" {
		update.Profile = stored.Profile
	}
}

func (s *ApiService) UpdateGlobalConfig(ctx context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
	if s.Globals == nil || req == nil || req.Config == nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, nil
	}
	stored := s.Globals.Get(ctx)
	KeepOmittedSections(req.Config, stored)
	// Every credential the caller read back as the placeholder, and sent back,
	// is the stored one again; one it cannot be is refused, naming it. This is
	// the save path REST, Connect and gRPC share. See ADR 0028.
	if err := storedsecret.Restore(req.Config, stored); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, status.Error(codes.InvalidArgument, err.Error())
	}

	// If audit signing is enabled with no key -- and none was stored, or
	// Restore would have kept it -- generate one BEFORE persisting, so it is
	// saved to disk and the chain stays verifiable across restarts.
	if a := req.Config.Audit; a != nil && a.SignEntries && a.SignatureKey == "" {
		a.SignatureKey = audit.GenerateSignatureKey()
	}

	if err := s.Globals.Update(ctx, req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, err
	}
	//nolint:contextcheck // IP reputation's Reconfigure starts a feed refresh that outlives this request, on purpose.
	s.applyGlobalConfig(req.Config)
	s.logAudit(ctx, "update", "global_config", "Updated global configuration")

	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}

// applyGlobalConfig reconfigures the running subsystems a stored update
// touches.
func (s *ApiService) applyGlobalConfig(c *gateonv1.GlobalConfig) {
	if c.Alerting != nil {
		alerting.UpdateConfig(c.Alerting, s.EbpfManager)
	}
	if c.Audit != nil {
		audit.UpdateConfig(c.Audit)
	}
	if c.SecurityAdvanced != nil && c.SecurityAdvanced.IpReputation != nil && s.IPReputation != nil {
		s.IPReputation.Reconfigure(c.SecurityAdvanced.IpReputation)
	}
	if l := c.Log; l != nil {
		telemetry.ConfigureGranularRetention(
			int(l.PathStatsRetentionDays),
			int(l.AccessLogRetentionDays),
			int(l.SecurityThreatRetentionDays),
			int(l.AuditLogRetentionDays),
		)
	}
	if c.Waf != nil {
		wafmw.InvalidateWAFCache()
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool { return true })
		if c.Tls != nil {
			s.Invalidator.InvalidateTLS()
		}
	}
	if g := c.Geoip; g != nil && g.Enabled && g.DbPath != "" {
		_ = telemetry.InitGeoIP(g.DbPath)
	}
	if s.EbpfManager != nil && c.Ebpf != nil {
		_ = s.EbpfManager.SetPortKnockingSequence(c.Ebpf.KnockingSequence)
	}
}
