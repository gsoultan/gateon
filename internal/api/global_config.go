// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) GetGlobalConfig(ctx context.Context, _ *gateonv1.GetGlobalConfigRequest) (*gateonv1.GetGlobalConfigResponse, error) {
	if s.Globals == nil {
		return &gateonv1.GetGlobalConfigResponse{Config: &gateonv1.GlobalConfig{}}, nil
	}
	conf := s.Globals.Get(ctx)
	if !callerMayWrite(ctx, auth.ResourceGlobal) {
		conf = RedactGlobalSecrets(conf)
	}
	return &gateonv1.GetGlobalConfigResponse{Config: conf}, nil
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

// RedactGlobalSecrets returns a copy of gc with every credential blanked.
//
// It is applied to a read by a caller who may not write the global
// configuration. The viewer role -- read-only by definition -- holds ActionRead
// on ResourceGlobal so the dashboard can render settings, and that read used
// to return the PASETO session key, the audit chain's HMAC signing key, the
// database and Redis passwords and every third-party API token verbatim. A
// role that cannot change a credential has no use for its value, and a role
// that can still receives it, so the settings editor round-trips unchanged.
//
// The copy is what makes this safe on the live config: the registry hands
// out its stored pointer, and blanking fields on that would erase the secrets
// from the running gateway.
func RedactGlobalSecrets(gc *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	if gc == nil {
		return nil
	}
	out, ok := proto.Clone(gc).(*gateonv1.GlobalConfig)
	if !ok {
		return &gateonv1.GlobalConfig{}
	}
	redactStorageSecrets(out)
	redactSecuritySecrets(out)
	return out
}

func redactStorageSecrets(out *gateonv1.GlobalConfig) {
	if a := out.Auth; a != nil {
		a.PasetoSecret, a.DatabaseUrl = "", ""
		if a.DatabaseConfig != nil {
			a.DatabaseConfig.Password = ""
		}
	}
	if a := out.Audit; a != nil {
		a.SignatureKey, a.DatabaseUrl = "", ""
		if a.DatabaseConfig != nil {
			a.DatabaseConfig.Password = ""
		}
	}
	if r := out.Redis; r != nil {
		r.Password = ""
	}
	if h := out.Ha; h != nil {
		h.AuthPass = ""
	}
	if g := out.Geoip; g != nil {
		g.MaxmindLicenseKey = ""
	}
	if m := out.Management; m != nil && m.Gitops != nil {
		m.Gitops.AuthToken = ""
	}
}

func redactSecuritySecrets(out *gateonv1.GlobalConfig) {
	if w := out.Waf; w != nil && w.BotManagement != nil {
		w.BotManagement.SecretKey = ""
	}
	if s := out.SecurityAdvanced; s != nil {
		if s.Deception != nil {
			s.Deception.CanaryToken = ""
		}
		if s.Pow != nil {
			s.Pow.Secret = ""
		}
		if s.IpReputation != nil {
			for _, i := range s.IpReputation.Integrations {
				i.ApiKey = ""
			}
		}
	}
	if al := out.Alerting; al != nil {
		for _, d := range al.Dispatchers {
			// A Slack or Discord incoming-webhook URL is the credential.
			d.TelegramBotToken, d.WebhookUrl = "", ""
		}
	}
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
	KeepOmittedSections(req.Config, s.Globals.Get(ctx))

	// If audit signing is enabled with no key, generate a random one BEFORE
	// persisting so it is saved to disk (chain stays verifiable across restarts)
	// and returned to the UI on the next GetGlobalConfig.
	if a := req.Config.Audit; a != nil && a.SignEntries && a.SignatureKey == "" {
		a.SignatureKey = audit.GenerateSignatureKey()
	}

	if err := s.Globals.Update(ctx, req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, err
	}

	// Trigger reconfigurations
	if req.Config.Alerting != nil {
		alerting.UpdateConfig(req.Config.Alerting, s.EbpfManager)
	}
	if req.Config.Audit != nil {
		audit.UpdateConfig(req.Config.Audit)
	}
	if req.Config.SecurityAdvanced != nil && req.Config.SecurityAdvanced.IpReputation != nil && s.IPReputation != nil {
		s.IPReputation.Reconfigure(req.Config.SecurityAdvanced.IpReputation)
	}

	// Update telemetry retention if log config is present
	if req.Config.Log != nil {
		l := req.Config.Log
		telemetry.ConfigureGranularRetention(
			int(l.PathStatsRetentionDays),
			int(l.AccessLogRetentionDays),
			int(l.SecurityThreatRetentionDays),
			int(l.AuditLogRetentionDays),
		)
	}

	// Invalidate cache if needed
	if s.Invalidator != nil {
		s.Invalidator.InvalidateRoutes(func(r *gateonv1.Route) bool { return true })
		if req.Config.Tls != nil {
			s.Invalidator.InvalidateTLS()
		}
	}

	// Update eBPF Port Knocking sequence
	if s.EbpfManager != nil && req.Config.Ebpf != nil {
		_ = s.EbpfManager.SetPortKnockingSequence(req.Config.Ebpf.KnockingSequence)
	}

	s.logAudit(ctx, "update", "global_config", "Updated global configuration")

	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}
