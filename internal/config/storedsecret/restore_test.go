// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package storedsecret

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func clone(c *gateonv1.GlobalConfig) *gateonv1.GlobalConfig {
	out, ok := proto.Clone(c).(*gateonv1.GlobalConfig)
	if !ok {
		panic("clone")
	}
	return out
}

// storedAndEcho is a stored config with a value in every credential field, and
// what a writer sends back after reading it and changing nothing.
func storedAndEcho(t *testing.T) (stored, echo *gateonv1.GlobalConfig) {
	t.Helper()
	stored = fullConfig()
	fill(t, stored)
	echo = clone(stored)
	Mask(echo)
	return stored, echo
}

// TestRestoreKeepsEveryStoredSecretForAnUnchangedEcho: read, change nothing,
// save. Every credential must come back exactly as it was stored.
func TestRestoreKeepsEveryStoredSecretForAnUnchangedEcho(t *testing.T) {
	stored, echo := storedAndEcho(t)
	if err := Restore(echo, stored); err != nil {
		t.Fatalf("an unchanged echo was refused: %v", err)
	}
	if !proto.Equal(echo, stored) {
		t.Fatalf("an unchanged echo did not restore the stored config:\n got %v\nwant %v", echo, stored)
	}
	if held := Held(echo); len(held) > 0 {
		t.Fatalf("the restored config still holds the placeholder in %v", held)
	}
}

// TestRestoreReplacesAndClears: a new value replaces, "" clears an optional
// credential, and "" keeps a key the gateway cannot give up.
func TestRestoreReplacesAndClears(t *testing.T) {
	stored, update := storedAndEcho(t)
	update.Redis.Password = "a-new-redis-password"
	update.Geoip.MaxmindLicenseKey = ""
	update.Alerting.Dispatchers[1].TelegramBotToken = ""
	update.Auth.PasetoSecret = ""
	update.Audit.SignatureKey = ""
	update.SecurityAdvanced.Pow.Secret = ""
	if err := Restore(update, stored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if update.Redis.Password != "a-new-redis-password" {
		t.Errorf("a new Redis password became %q", update.Redis.Password)
	}
	if update.Geoip.MaxmindLicenseKey != "" || update.Alerting.Dispatchers[1].TelegramBotToken != "" {
		t.Error("an optional credential sent as \"\" was not cleared")
	}
	for name, pair := range map[string][2]string{
		"auth.paseto_secret":           {update.Auth.PasetoSecret, stored.Auth.PasetoSecret},
		"audit.signature_key":          {update.Audit.SignatureKey, stored.Audit.SignatureKey},
		"security_advanced.pow.secret": {update.SecurityAdvanced.Pow.Secret, stored.SecurityAdvanced.Pow.Secret},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s sent as \"\" became %q; a required key must be kept", name, pair[0])
		}
	}
}

// TestRestoreRefusesAPlaceholderWithNothingStored: the placeholder asks to keep
// a secret; with none stored there is nothing to keep, and storing "" in its
// place would read as success.
func TestRestoreRefusesAPlaceholderWithNothingStored(t *testing.T) {
	stored := fullConfig()
	update := fullConfig()
	update.Redis.Password = Sentinel
	err := Restore(update, stored)
	if !errors.Is(err, ErrNothingStored) || !strings.Contains(err.Error(), "redis.password") {
		t.Fatalf("Restore = %v; want ErrNothingStored naming redis.password", err)
	}
}

// TestRestoreRefusesAKeptSecretWhoseDestinationMoved is the attack a
// write-only secret has to survive: point the Redis address, the database
// host, the repository or the provider somewhere the caller controls, keep the
// stored credential, and let the gateway deliver it.
func TestRestoreRefusesAKeptSecretWhoseDestinationMoved(t *testing.T) {
	for name, move := range map[string]func(c *gateonv1.GlobalConfig){
		"redis.password":                 func(c *gateonv1.GlobalConfig) { c.Redis.Addr = "evil.example:6379" },
		"auth.database_config.password":  func(c *gateonv1.GlobalConfig) { c.Auth.DatabaseConfig.Host = "evil.example" },
		"audit.database_config.password": func(c *gateonv1.GlobalConfig) { c.Audit.DatabaseConfig.Port = 6543 },
		"auth.database_url": func(c *gateonv1.GlobalConfig) {
			c.Auth.DatabaseUrl = strings.Replace(c.Auth.DatabaseUrl, "db.internal", "evil.example", 1)
		},
		"management.gitops.auth_token": func(c *gateonv1.GlobalConfig) {
			c.Management.Gitops.RepositoryUrl = "https://evil.example/org/repo.git"
		},
		"security_advanced.ip_reputation.integrations": func(c *gateonv1.GlobalConfig) {
			c.SecurityAdvanced.IpReputation.Integrations[0].Type = "virustotal"
		},
	} {
		t.Run(name, func(t *testing.T) {
			stored, update := storedAndEcho(t)
			stored.Management.Gitops.RepositoryUrl = "https://git.example/org/repo.git"
			update.Management.Gitops.RepositoryUrl = stored.Management.Gitops.RepositoryUrl
			move(update)
			err := Restore(update, stored)
			if !errors.Is(err, ErrMoved) || !strings.Contains(err.Error(), name) {
				t.Fatalf("Restore = %v; want ErrMoved naming %s", err, name)
			}
		})
	}
}

// TestRestoreMatchesListElementsByID: reorder, rename and delete elements, and
// each keeps its own secret -- by id, never by position.
func TestRestoreMatchesListElementsByID(t *testing.T) {
	stored, update := storedAndEcho(t)
	d := update.Alerting.Dispatchers
	d[0].Name, d[1].Name = "renamed-ops", "renamed-on-call"
	update.Alerting.Dispatchers = []*gateonv1.AlertDispatcher{d[1], d[0]}
	update.SecurityAdvanced.IpReputation.Integrations = update.SecurityAdvanced.IpReputation.Integrations[1:]
	if err := Restore(update, stored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, got := range update.Alerting.Dispatchers {
		want := storedDispatcher(t, stored, got.Id)
		if got.WebhookUrl != want.WebhookUrl || got.TelegramBotToken != want.TelegramBotToken {
			t.Errorf("dispatcher %s got another element's secrets", got.Id)
		}
	}
	kept := update.SecurityAdvanced.IpReputation.Integrations[0]
	if kept.Id != "rep-2" || kept.ApiKey != stored.SecurityAdvanced.IpReputation.Integrations[1].ApiKey {
		t.Errorf("after deleting rep-1, rep-2 holds %q, not its own key", kept.ApiKey)
	}
}

func storedDispatcher(t *testing.T, c *gateonv1.GlobalConfig, id string) *gateonv1.AlertDispatcher {
	t.Helper()
	for _, d := range c.Alerting.Dispatchers {
		if d.Id == id {
			return d
		}
	}
	t.Fatalf("no stored dispatcher %s", id)
	return nil
}

// TestRestoreRefusesAnElementItCannotMatch names the element in every case:
// an id nobody has, no id at all, and an id two stored elements share.
func TestRestoreRefusesAnElementItCannotMatch(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(stored, update *gateonv1.GlobalConfig)
		want   string
	}{
		"unknown id": {func(_, u *gateonv1.GlobalConfig) { u.Alerting.Dispatchers[0].Id = "d-9" },
			`alerting.dispatchers[id "d-9", name "ops"]`},
		"no id": {func(_, u *gateonv1.GlobalConfig) { u.Alerting.Dispatchers[1].Id = "" },
			`alerting.dispatchers[1] (name "on-call")`},
		"shared id": {func(s, _ *gateonv1.GlobalConfig) { s.Alerting.Dispatchers[1].Id = "d-1" },
			`alerting.dispatchers[id "d-1", name "ops"]`},
	} {
		t.Run(name, func(t *testing.T) {
			stored, update := storedAndEcho(t)
			tc.change(stored, update)
			err := Restore(update, stored)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Restore = %v; want a refusal naming %s", err, tc.want)
			}
		})
	}
}

// TestRestoreRefusesAPlaceholderInsideANewValue: a value that contains the
// placeholder is neither a new secret nor a request to keep the stored one.
func TestRestoreRefusesAPlaceholderInsideANewValue(t *testing.T) {
	stored, update := storedAndEcho(t)
	update.Redis.Password = "prefix" + Sentinel
	if err := Restore(update, stored); !errors.Is(err, ErrPartialPlaceholder) {
		t.Fatalf("Restore = %v; want ErrPartialPlaceholder", err)
	}
}

// TestRestoreKeepsAReference: a referenced secret reads as its reference and
// is saved back as it; the placeholder for one keeps the reference.
func TestRestoreKeepsAReference(t *testing.T) {
	stored := fullConfig()
	stored.Redis.Password = "$env:GATEON_REDIS_PASSWORD"
	stored.Alerting.Dispatchers[0].WebhookUrl = "$vault:secret/data/alerts#slack"
	echo := clone(stored)
	Mask(echo)
	echo.Alerting.Dispatchers[0].WebhookUrl = Sentinel
	if err := Restore(echo, stored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if echo.Redis.Password != stored.Redis.Password || echo.Alerting.Dispatchers[0].WebhookUrl != stored.Alerting.Dispatchers[0].WebhookUrl {
		t.Fatalf("references did not round-trip: %q, %q", echo.Redis.Password, echo.Alerting.Dispatchers[0].WebhookUrl)
	}
}

// TestHeldNamesEveryPlaceholder is the store's guard: a config that would
// persist the placeholder as a secret is named field by field.
func TestHeldNamesEveryPlaceholder(t *testing.T) {
	c := fullConfig()
	c.Auth.PasetoSecret = Sentinel
	c.Auth.DatabaseUrl = "postgres://gateon:" + Sentinel + "@db/gateon"
	c.Alerting.Dispatchers[1].TelegramBotToken = Sentinel
	got := strings.Join(Held(c), "; ")
	for _, want := range []string{"auth.paseto_secret", "auth.database_url", `alerting.dispatchers[id "d-2", name "on-call"].telegram_bot_token`} {
		if !strings.Contains(got, want) {
			t.Errorf("Held = %s; missing %s", got, want)
		}
	}
	if held := Held(fullConfig()); len(held) != 0 {
		t.Errorf("Held names %v in a config with no placeholder", held)
	}
}

// TestAssignIDsNamesOnlyElementsWithoutOne, and names them the same way every
// time, so an id seen on one start is the one the next start matches.
func TestAssignIDsNamesOnlyElementsWithoutOne(t *testing.T) {
	c := fullConfig()
	c.Alerting.Dispatchers[1].Id = ""
	AssignIDs(c)
	first := c.Alerting.Dispatchers[1].Id
	if first == "" || c.Alerting.Dispatchers[0].Id != "d-1" {
		t.Fatalf("ids after AssignIDs: %q, %q", c.Alerting.Dispatchers[0].Id, first)
	}
	again := fullConfig()
	again.Alerting.Dispatchers[1].Id = ""
	AssignIDs(again)
	if again.Alerting.Dispatchers[1].Id != first {
		t.Fatalf("the derived id changed between two loads: %q then %q", first, again.Alerting.Dispatchers[1].Id)
	}
}
