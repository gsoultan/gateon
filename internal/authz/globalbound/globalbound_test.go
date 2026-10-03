// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package globalbound

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	operator = Caller{Claims: &auth.Claims{ID: "op-1", Role: auth.RoleOperator}, ClaimsPresent: true, AuthEnforced: true}
	admin    = Caller{Claims: &auth.Claims{ID: "ad-1", Role: auth.RoleAdmin}, ClaimsPresent: true, AuthEnforced: true}
)

// storedConfig is a configuration with every section the boundary cases touch
// populated, so a change is a change of a real value.
func storedConfig() *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{
		Auth:  &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
		Audit: &gateonv1.AuditConfig{Enabled: true, SignEntries: true, SignatureKey: "audit-key", RetentionDays: 90},
		Rbac:  &gateonv1.RBACConfig{Enabled: true, Roles: []*gateonv1.RolePolicy{{Role: "operator"}}},
		Management: &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: "8080", AllowedIps: []string{"10.0.0.0/8"},
			Cors: &gateonv1.CorsConfig{AllowedOrigins: []string{"https://admin.example"}}},
		Log:      &gateonv1.LogConfig{Level: "info", AuditLogRetentionDays: 365},
		Waf:      &gateonv1.WafConfig{Enabled: true, ParanoiaLevel: 1},
		Tls:      &gateonv1.TlsConfig{Enabled: true, ClientAuthType: "NoClientCert"},
		Ebpf:     &gateonv1.EbpfConfig{Enabled: true, EnableMgmtWhitelist: true, MgmtWhitelistIps: []string{"10.0.0.1"}},
		Redis:    &gateonv1.RedisConfig{Enabled: true, Addr: "redis.internal:6379"},
		Debugger: &gateonv1.DebuggerConfig{MaxBodySize: 1024},
		Geoip:    &gateonv1.GeoIPConfig{Enabled: true},
		Profile:  "standard",
	}
}

func proposedFrom(stored *gateonv1.GlobalConfig, mutate func(*gateonv1.GlobalConfig)) *gateonv1.GlobalConfig {
	out, ok := proto.Clone(stored).(*gateonv1.GlobalConfig)
	if !ok {
		panic("clone")
	}
	mutate(out)
	return out
}

// boundaryCases are the changes ADR 0040 makes administrator-only, each with
// the field a refusal must name.
var boundaryCases = []struct {
	field  string
	mutate func(*gateonv1.GlobalConfig)
}{
	{"auth.enabled", func(c *gateonv1.GlobalConfig) { c.Auth.Enabled = false }},
	{"auth.paseto_secret", func(c *gateonv1.GlobalConfig) { c.Auth.PasetoSecret = "fedcba9876543210fedcba9876543210" }},
	{"auth.database_config.host", func(c *gateonv1.GlobalConfig) {
		c.Auth.DatabaseConfig = &gateonv1.DatabaseConfig{Host: "evil.example"}
	}},
	{"rbac.roles", func(c *gateonv1.GlobalConfig) {
		c.Rbac.Roles = []*gateonv1.RolePolicy{{Role: "operator", Permissions: []*gateonv1.Permission{{Resource: "*", Action: "*"}}}}
	}},
	{"rbac.enabled", func(c *gateonv1.GlobalConfig) { c.Rbac.Enabled = false }},
	{"audit.enabled", func(c *gateonv1.GlobalConfig) { c.Audit.Enabled = false }},
	{"audit.signature_key", func(c *gateonv1.GlobalConfig) { c.Audit.SignatureKey = "attacker-key" }},
	{"log.audit_log_retention_days", func(c *gateonv1.GlobalConfig) { c.Log.AuditLogRetentionDays = 1 }},
	{"management.allowed_ips", func(c *gateonv1.GlobalConfig) { c.Management.AllowedIps = []string{"0.0.0.0/0"} }},
	{"management.bind", func(c *gateonv1.GlobalConfig) { c.Management.Bind = "0.0.0.0" }},
	{"management.cors.allowed_origins", func(c *gateonv1.GlobalConfig) {
		c.Management.Cors.AllowedOrigins = []string{"https://evil.example"}
	}},
	{"management.allow_public_management", func(c *gateonv1.GlobalConfig) { c.Management.AllowPublicManagement = true }},
	{"management.gitops.repository_url", func(c *gateonv1.GlobalConfig) {
		c.Management.Gitops = &gateonv1.GitOpsConfig{RepositoryUrl: "https://evil.example/config.git"}
	}},
	{"waf.trust_cloudflare_headers", func(c *gateonv1.GlobalConfig) { c.Waf.TrustCloudflareHeaders = true }},
	{"waf.audit_log_path", func(c *gateonv1.GlobalConfig) { c.Waf.AuditLogPath = "/root/.ssh/authorized_keys" }},
	{"tls.client_auth_type", func(c *gateonv1.GlobalConfig) { c.Tls.ClientAuthType = "RequestClientCert" }},
	{"tls.client_authorities", func(c *gateonv1.GlobalConfig) {
		c.Tls.ClientAuthorities = []*gateonv1.ClientAuthority{{Id: "evil", CaFile: "/tmp/evil.pem"}}
	}},
	{"ebpf.mgmt_whitelist_ips", func(c *gateonv1.GlobalConfig) { c.Ebpf.MgmtWhitelistIps = nil }},
	{"ebpf.enabled", func(c *gateonv1.GlobalConfig) { c.Ebpf.Enabled = false }},
	{"redis.addr", func(c *gateonv1.GlobalConfig) { c.Redis.Addr = "evil.example:6379" }},
	{"debugger.enabled", func(c *gateonv1.GlobalConfig) { c.Debugger.Enabled = true }},
}

func TestOperatorChangingABoundaryFieldIsRefusedAndNamed(t *testing.T) {
	for _, tc := range boundaryCases {
		t.Run(tc.field, func(t *testing.T) {
			stored := storedConfig()
			ch := Change{Stored: stored, Proposed: proposedFrom(stored, tc.mutate)}
			err := Authorize(operator, ch)
			if !errors.Is(err, ErrRequiresAdmin) {
				t.Fatalf("an operator changing %s was not refused: %v", tc.field, err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("the refusal does not name %s: %v", tc.field, err)
			}
			if err := Authorize(admin, ch); err != nil {
				t.Fatalf("an administrator changing %s was refused: %v", tc.field, err)
			}
		})
	}
}

// TestOperatorSavingTheWholeObjectWithAnOperationalChangeSucceeds is the
// dashboard's shape: every section sent back, one operational setting edited.
func TestOperatorSavingTheWholeObjectWithAnOperationalChangeSucceeds(t *testing.T) {
	stored := storedConfig()
	proposed := proposedFrom(stored, func(c *gateonv1.GlobalConfig) {
		c.Waf.ParanoiaLevel = 3
		c.Log.Level = "debug"
		c.Geoip.BlockedCountries = []string{"XX"}
		c.Redis.Enabled = false
		c.Debugger.MaxBodySize = 4096
		c.Profile = "enterprise"
	})
	if err := Authorize(operator, Change{Stored: stored, Proposed: proposed}); err != nil {
		t.Fatalf("an operator's operational change was refused: %v", err)
	}
}

// TestAReferenceSentBackUnchangedIsNotAChange: a writer reads a secret that
// was configured as a reference as the reference, and sends it back.
func TestAReferenceSentBackUnchangedIsNotAChange(t *testing.T) {
	stored := storedConfig()
	view := proposedFrom(stored, func(c *gateonv1.GlobalConfig) { c.Auth.PasetoSecret = "$env:GATEON_SESSION_KEY" })
	proposed := proposedFrom(view, func(c *gateonv1.GlobalConfig) { c.Waf.ParanoiaLevel = 2 })
	if err := Authorize(operator, Change{Stored: stored, View: view, Proposed: proposed}); err != nil {
		t.Fatalf("a reference sent back unchanged was read as a change: %v", err)
	}
	other := proposedFrom(view, func(c *gateonv1.GlobalConfig) { c.Auth.PasetoSecret = "$env:SOMETHING_ELSE" })
	if err := Authorize(operator, Change{Stored: stored, View: view, Proposed: other}); !errors.Is(err, ErrRequiresAdmin) {
		t.Fatalf("a different reference was not refused: %v", err)
	}
}

// TestAnAbsentSectionAndAnEmptyOneAreTheSame: a client that sends an empty
// section where none is stored has changed nothing.
func TestAnAbsentSectionAndAnEmptyOneAreTheSame(t *testing.T) {
	stored := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	proposed := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true},
		Audit: &gateonv1.AuditConfig{}, Management: &gateonv1.ManagementConfig{Cors: &gateonv1.CorsConfig{}}}
	if err := Authorize(operator, Change{Stored: stored, Proposed: proposed}); err != nil {
		t.Fatalf("an empty section where none was stored was read as a change: %v", err)
	}
}

func TestCallerThatCannotBeReadIsNotAnAdministrator(t *testing.T) {
	stored := storedConfig()
	ch := Change{Stored: stored, Proposed: proposedFrom(stored, boundaryCases[0].mutate)}
	cases := []struct {
		name   string
		caller Caller
		refuse bool
	}{
		{"claims present but unreadable", Caller{ClaimsPresent: true, AuthEnforced: true}, true},
		{"claims present but unreadable, auth off", Caller{ClaimsPresent: true}, true},
		{"no claims while authentication is in force", Caller{AuthEnforced: true}, true},
		{"viewer", Caller{Claims: &auth.Claims{Role: auth.RoleViewer}, ClaimsPresent: true}, true},
		{"no claims, authentication off", Caller{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Authorize(tc.caller, ch)
			if got := errors.Is(err, ErrRequiresAdmin); got != tc.refuse {
				t.Fatalf("refused=%v, want %v (err %v)", got, tc.refuse, err)
			}
		})
	}
}

// TestAFieldTheTableDoesNotNameIsAdministratorOnly: a field outside the table
// is enforced as Boundary, so forgetting to classify one fails closed.
func TestAFieldTheTableDoesNotNameIsAdministratorOnly(t *testing.T) {
	fd := (&gateonv1.Route{}).ProtoReflect().Descriptor().Fields().ByName("service_id")
	if ClassOf(fd) != Unclassified {
		t.Fatalf("route.service_id is classified; pick a field outside GlobalConfig")
	}
	if effective(fd) != Boundary {
		t.Fatalf("an unclassified field is enforced as %v, want Boundary", effective(fd))
	}
}

func TestChangingTheAuditSettingsIsDescribedWithoutTheirSecrets(t *testing.T) {
	stored := storedConfig()
	proposed := proposedFrom(stored, func(c *gateonv1.GlobalConfig) {
		c.Audit.Enabled = false
		c.Audit.SignatureKey = "a-new-signing-key"
		c.Log.AuditLogRetentionDays = 1
		c.Log.Level = "debug"
	})
	got := DescribeRecordChanges(RecordChanges(Change{Stored: stored, Proposed: proposed}))
	for _, want := range []string{"audit.enabled true -> false", "audit.signature_key changed", "log.audit_log_retention_days 365 -> 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("description %q lacks %q", got, want)
		}
	}
	for _, leak := range []string{"a-new-signing-key", "audit-key", "log.level"} {
		if strings.Contains(got, leak) {
			t.Errorf("description %q carries %q", got, leak)
		}
	}
	if n := len(RecordChanges(Change{Stored: stored, Proposed: proposedFrom(stored, func(*gateonv1.GlobalConfig) {})})); n != 0 {
		t.Errorf("an unchanged save reported %d audit-setting changes", n)
	}
}

// TestEveryGlobalFieldIsClassified walks the GlobalConfig descriptor and fails
// on any field the table does not classify, so a field added to the proto
// cannot default to operator-writable without a decision. Inside an
// Operational message every field must be Operational too, because the save
// does not look inside one; inside a Boundary one nothing is required, since
// the whole subtree is compared.
func TestEveryGlobalFieldIsClassified(t *testing.T) {
	root := (&gateonv1.GlobalConfig{}).ProtoReflect().Descriptor()
	seen := map[protoreflect.FullName]bool{}
	checkFields(t, root, Section, seen)
	for name := range classes {
		if !seen[name] {
			t.Errorf("%s is classified but not reachable from GlobalConfig: remove it", name)
		}
	}
}

func checkFields(t *testing.T, md protoreflect.MessageDescriptor, parent Class, seen map[protoreflect.FullName]bool) {
	t.Helper()
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		seen[fd.FullName()] = true
		c := ClassOf(fd)
		switch {
		case c == Unclassified:
			t.Errorf("%s is not classified: add it to classes in classes.go as Boundary or Operational (ADR 0040)", fd.FullName())
		case parent == Operational && c != Operational:
			t.Errorf("%s is %v inside an Operational message, whose fields are never compared: "+
				"make the parent a Section", fd.FullName(), c)
		case c == Section && !singularMessage(fd):
			t.Errorf("%s is a Section but not a singular message", fd.FullName())
		}
		if fd.Message() != nil && c != Boundary {
			checkFields(t, fd.Message(), c, seen)
		}
	}
}
