// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package storedsecret

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fullConfig has every section that holds a credential, and two elements in
// each credential-carrying list.
func fullConfig() *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, DatabaseConfig: &gateonv1.DatabaseConfig{
			Driver: "postgres", Host: "db.internal", Port: 5432, User: "gateon", Database: "gateon"}},
		Audit: &gateonv1.AuditConfig{SignEntries: true, DatabaseConfig: &gateonv1.DatabaseConfig{
			Driver: "postgres", Host: "audit.internal", Port: 5432, User: "audit", Database: "audit"}},
		Redis:      &gateonv1.RedisConfig{Enabled: true, Addr: "redis.internal:6379"},
		Ha:         &gateonv1.HaConfig{Enabled: true},
		Geoip:      &gateonv1.GeoIPConfig{Enabled: true},
		Management: &gateonv1.ManagementConfig{Gitops: &gateonv1.GitOpsConfig{Enabled: true}},
		Waf:        &gateonv1.WafConfig{BotManagement: &gateonv1.BotManagementConfig{Enabled: true}},
		SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
			Deception: &gateonv1.DeceptionConfig{Enabled: true},
			Pow:       &gateonv1.PowConfig{Enabled: true},
			IpReputation: &gateonv1.IPReputationConfig{Integrations: []*gateonv1.IPReputationIntegration{
				{Id: "rep-1", Name: "AbuseIPDB", Type: "abuseipdb", Enabled: true},
				{Id: "rep-2", Name: "VirusTotal", Type: "virustotal", Enabled: true},
			}},
		},
		Alerting: &gateonv1.AlertingConfig{Dispatchers: []*gateonv1.AlertDispatcher{
			{Id: "d-1", Name: "ops", Type: "slack"},
			{Id: "d-2", Name: "on-call", Type: "telegram", TelegramChatId: "42"},
		}},
	}
}

func randomValue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "S3CR3T" + hex.EncodeToString(b)
}

// fill stores a distinct random value in every credential field of c and
// returns them. A connection URL gets its value as the password inside a URL,
// which is the part that is secret.
func fill(t *testing.T, c *gateonv1.GlobalConfig) []string {
	t.Helper()
	var values []string
	for _, f := range Fields() {
		p := f.Ptr(c)
		if p == nil {
			t.Fatalf("fullConfig has no section for %s; add it", f.Name)
		}
		v := randomValue(t)
		values = append(values, v)
		if f.URL {
			*p = "postgres://gateon:" + v + "@db.internal:5432/gateon"
			continue
		}
		*p = v
	}
	for _, l := range Lists() {
		elements := l.Elements(c)
		if len(elements) == 0 {
			t.Fatalf("fullConfig has no element in %s; add one", l.Name)
		}
		for _, e := range elements {
			for _, s := range e.Secrets {
				v := randomValue(t)
				values = append(values, v)
				*s.Ptr = v
			}
		}
	}
	return values
}

// TestSentinelMatchesTheDashboard keeps the Go and TypeScript spellings of the
// placeholder equal. They are two literals in two languages; if they drifted,
// the dashboard would show a stored secret's placeholder as if it were a value
// the operator typed, and send it back as a new value to be refused.
func TestSentinelMatchesTheDashboard(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "ui", "src", "utils", "storedSecret.ts"))
	if err != nil {
		t.Fatalf("read the dashboard's constant: %v", err)
	}
	m := regexp.MustCompile(`export const STORED_SECRET_SENTINEL = "([^"]*)";`).FindSubmatch(src)
	if m == nil {
		t.Fatal("ui/src/utils/storedSecret.ts no longer declares STORED_SECRET_SENTINEL as a string literal")
	}
	if got := string(m[1]); got != Sentinel {
		t.Fatalf("the dashboard's STORED_SECRET_SENTINEL is %q; the gateway's Sentinel is %q", got, Sentinel)
	}
}

// credentialName matches the field names that suggest a credential.
var credentialName = regexp.MustCompile(`secret|pass|token|key|webhook|url|dsn|cred|auth`)

// notCredentials are string fields whose names match credentialName and which
// hold no credential. Each says why.
var notCredentials = map[string]string{
	"tls.client_auth_type":                      "a verification mode",
	"tls.certificates.key_file":                 "a path to the key file, not the key",
	"security_advanced.ip_reputation.feed_urls": "public blocklist feed addresses",
}

// TestEveryCredentialFieldIsCovered walks every string field of GlobalConfig
// and requires each whose name suggests a credential to be in the table --
// masked on read, restored on save, never persisted as the placeholder -- or
// named in notCredentials with a reason. A credential added to the proto and
// not to the table used to reach every writer verbatim; now it fails here.
func TestEveryCredentialFieldIsCovered(t *testing.T) {
	covered := map[string]bool{}
	for _, f := range Fields() {
		covered[f.Name] = true
	}
	for _, l := range Lists() {
		for _, e := range l.Elements(fullConfig()) {
			for _, s := range e.Secrets {
				covered[l.Name+"."+s.Name] = true
			}
		}
	}
	var names []string
	stringFields((&gateonv1.GlobalConfig{}).ProtoReflect().Descriptor(), "", map[protoreflect.FullName]bool{}, &names)
	for _, name := range names {
		leaf := name[strings.LastIndex(name, ".")+1:]
		if !credentialName.MatchString(leaf) || covered[name] {
			continue
		}
		if _, ok := notCredentials[name]; !ok {
			t.Errorf("%s looks like a credential and is neither in storedsecret's table nor in notCredentials", name)
		}
	}
	for name := range covered {
		if !slices.Contains(names, name) {
			t.Errorf("the table names %s, which GlobalConfig does not have", name)
		}
	}
}

func stringFields(md protoreflect.MessageDescriptor, prefix string, seen map[protoreflect.FullName]bool, out *[]string) {
	if seen[md.FullName()] {
		return
	}
	seen[md.FullName()] = true
	defer delete(seen, md.FullName())
	for i := range md.Fields().Len() {
		f := md.Fields().Get(i)
		name := prefix + string(f.Name())
		switch {
		case f.IsMap():
		case f.Kind() == protoreflect.MessageKind:
			stringFields(f.Message(), name+".", seen, out)
		case f.Kind() == protoreflect.StringKind:
			*out = append(*out, name)
		}
	}
}

// TestMaskGivesAWriterNoStoredValue is the read half of the contract: with a
// distinct value in every credential field, nothing Mask leaves behind
// contains any of them, and each field reads as the placeholder.
func TestMaskGivesAWriterNoStoredValue(t *testing.T) {
	c := fullConfig()
	values := fill(t, c)
	Mask(c)
	out := protojson.Format(c)
	for _, v := range values {
		if strings.Contains(out, v) {
			t.Errorf("a masked config still carries the stored value %q", v)
		}
	}
	for _, f := range Fields() {
		got := *f.Ptr(c)
		want := Sentinel
		if f.URL {
			want = "postgres://gateon:" + Sentinel + "@db.internal:5432/gateon"
		}
		if got != want {
			t.Errorf("%s reads %q, want %q", f.Name, got, want)
		}
	}
	for _, l := range Lists() {
		for _, e := range l.Elements(c) {
			for _, s := range e.Secrets {
				if *s.Ptr != Sentinel {
					t.Errorf("%s[%s].%s reads %q, want the placeholder", l.Name, *e.ID, s.Name, *s.Ptr)
				}
			}
		}
	}
}

// TestMaskShowsAReferenceAndAnUnsetField: a reference names a secret without
// being one, and saving it back must store the reference; an unset field must
// read as unset, not as "something is stored".
func TestMaskShowsAReferenceAndAnUnsetField(t *testing.T) {
	c := fullConfig()
	c.Redis.Password = "$env:GATEON_REDIS_PASSWORD"
	c.Alerting.Dispatchers[0].WebhookUrl = "$vault:secret/data/alerts#slack"
	Mask(c)
	if c.Redis.Password != "$env:GATEON_REDIS_PASSWORD" {
		t.Errorf("a referenced password reads %q, want the reference", c.Redis.Password)
	}
	if c.Alerting.Dispatchers[0].WebhookUrl != "$vault:secret/data/alerts#slack" {
		t.Errorf("a referenced webhook reads %q, want the reference", c.Alerting.Dispatchers[0].WebhookUrl)
	}
	if c.Auth.PasetoSecret != "" || c.Alerting.Dispatchers[1].TelegramBotToken != "" {
		t.Error("an unset credential reads as set")
	}
}

// TestBlankEmptiesEveryCredential is what a viewer reads.
func TestBlankEmptiesEveryCredential(t *testing.T) {
	c := fullConfig()
	values := fill(t, c)
	c.Redis.Password = "$env:GATEON_REDIS_PASSWORD"
	Blank(c)
	out := protojson.Format(c)
	for _, v := range append(values, "GATEON_REDIS_PASSWORD", Sentinel) {
		if strings.Contains(out, v) {
			t.Errorf("a blanked config still carries %q", v)
		}
	}
}

func TestMaskURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"postgres://gateon:pw@db/gateon?sslmode=disable", "postgres://gateon:" + Sentinel + "@db/gateon?sslmode=disable"},
		{"postgres://gateon:p@ss@db:5432/gateon", "postgres://gateon:" + Sentinel + "@db:5432/gateon"},
		{"https://x-access-token:ghp_abc@github.com/org/repo.git", "https://x-access-token:" + Sentinel + "@github.com/org/repo.git"},
		{"postgres://db/gateon?sslmode=disable", "postgres://db/gateon?sslmode=disable"},
		{"postgres://gateon@db/gateon", "postgres://gateon@db/gateon"},
		{"gateon.db", "gateon.db"},
		{"sqlite:/var/lib/gateon/gateon.db", "sqlite:/var/lib/gateon/gateon.db"},
		// Hidden whole: a password the URL grammar cannot delimit.
		{"postgres://gateon:pa/ss@db/gateon", Sentinel},
		{"postgres://gateon:pa#ss@db/gateon", Sentinel},
		{"postgres://db/gateon?password=pw", Sentinel},
		{"host=db user=gateon password=pw dbname=gateon", Sentinel},
		{"gateon:pw@tcp(db:3306)/gateon", Sentinel},
	} {
		if got := masked(tc.in, true); got != tc.want {
			t.Errorf("masked(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
