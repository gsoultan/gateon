// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package storedsecret keeps the global configuration's credentials on the
// gateway's side of the management API. See ADR 0028.
//
// A caller who may write the configuration reads every stored credential as
// Sentinel -- or as the reference it was configured with ($env:NAME and the
// like), which names a secret without being one -- and sends Sentinel back to
// keep it. A caller who may only read it reads "". Nothing the API returns
// carries a stored credential, so a stolen administrator session, or script
// running in the dashboard, can replace one but cannot learn one.
package storedsecret

import (
	"errors"
	"strings"

	"github.com/gsoultan/gateon/internal/security/secretmask"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Sentinel is what the management API returns in place of a stored secret,
// and what a client sends back to keep it.
//
// It is the placeholder the middleware API uses for the same purpose
// (secretmask.Placeholder, restored by mwsecret.Restore), so a client learns
// one convention for the whole API. It is reserved rather than merely
// unlikely: the registry refuses to store it as a secret (Held), so no stored
// secret can equal it, and a value that does can only mean "the one already
// stored". It is not the shape of a 32-byte session key, a hex audit key or a
// bot token, and it says what it is to a person reading the JSON.
//
// The dashboard holds the same string as STORED_SECRET_SENTINEL in
// ui/src/utils/storedSecret.ts; a test in this package keeps the two equal.
const Sentinel = secretmask.Placeholder

var (
	// ErrNothingStored refuses Sentinel where no secret is stored to keep.
	ErrNothingStored = errors.New("the placeholder keeps a stored secret, and none is stored here; enter the value")
	// ErrMoved refuses Sentinel for a secret whose destination the same update
	// changes. Keeping it would send the stored credential to wherever the
	// caller pointed it, which is how a write-only secret gets read.
	ErrMoved = errors.New("the stored secret is kept only for the destination it was entered for, and this update " +
		"changes that destination; enter the secret again")
	// ErrPartialPlaceholder refuses a value that contains Sentinel without
	// being it, other than a connection URL whose password it stands for.
	ErrPartialPlaceholder = errors.New("the value contains the stored-secret placeholder but is not it; send the " +
		"placeholder alone to keep the stored secret, or a complete new value")
	// ErrPlaceholderStored is the store's refusal to persist Sentinel as a
	// secret, whichever path tried to.
	ErrPlaceholderStored = errors.New("refusing to store the stored-secret placeholder as a secret")
)

// referencePrefixes are the value prefixes that name a secret held elsewhere
// rather than being the secret.
var referencePrefixes = []string{"$env:", "$vault:", "$aws-sm:"}

// IsReference reports whether s names a secret held elsewhere.
func IsReference(s string) bool {
	return ReferenceKind(s) != ""
}

// ReferenceKind is the prefix of a reference, or "" for a value that is not
// one. The prefix is safe to log where the rest -- a path or variable name --
// may not be.
func ReferenceKind(s string) string {
	for _, p := range referencePrefixes {
		if strings.HasPrefix(s, p) {
			return p
		}
	}
	return ""
}

// Field is one credential field of a GlobalConfig.
type Field struct {
	// Name is the field's path in the proto, which is how refusals name it.
	Name string
	// Ptr finds the field in c, or returns nil when its section is absent.
	Ptr func(c *gateonv1.GlobalConfig) *string
	// Required marks a key the gateway cannot give up: an update that leaves
	// it empty keeps the stored key instead of clearing it.
	Required bool
	// URL marks a connection URL. Only a password in it is secret, so the
	// rest -- driver, host, database -- stays readable.
	URL bool
	// Destination names where the gateway sends the secret, when the
	// configuration chooses that; nil when the secret stays in the gateway or
	// goes to a fixed address. A kept secret must go where it went before.
	Destination func(c *gateonv1.GlobalConfig) string
}

// Fields lists every credential field of a GlobalConfig outside a list.
// Lists holds the ones inside list elements.
func Fields() []Field { return fields }

var fields = []Field{
	{Name: "auth.paseto_secret", Required: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if a := c.GetAuth(); a != nil {
			return &a.PasetoSecret
		}
		return nil
	}},
	{Name: "auth.database_url", URL: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if a := c.GetAuth(); a != nil {
			return &a.DatabaseUrl
		}
		return nil
	}},
	{Name: "auth.database_config.password", Destination: func(c *gateonv1.GlobalConfig) string {
		return databaseAddress(c.GetAuth().GetDatabaseConfig())
	}, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if d := c.GetAuth().GetDatabaseConfig(); d != nil {
			return &d.Password
		}
		return nil
	}},
	{Name: "audit.signature_key", Required: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if a := c.GetAudit(); a != nil {
			return &a.SignatureKey
		}
		return nil
	}},
	{Name: "audit.database_url", URL: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if a := c.GetAudit(); a != nil {
			return &a.DatabaseUrl
		}
		return nil
	}},
	{Name: "audit.database_config.password", Destination: func(c *gateonv1.GlobalConfig) string {
		return databaseAddress(c.GetAudit().GetDatabaseConfig())
	}, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if d := c.GetAudit().GetDatabaseConfig(); d != nil {
			return &d.Password
		}
		return nil
	}},
	{Name: "redis.password", Destination: func(c *gateonv1.GlobalConfig) string {
		return strings.ToLower(strings.TrimSpace(c.GetRedis().GetAddr()))
	}, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if r := c.GetRedis(); r != nil {
			return &r.Password
		}
		return nil
	}},
	{Name: "ha.auth_pass", Ptr: func(c *gateonv1.GlobalConfig) *string {
		if h := c.GetHa(); h != nil {
			return &h.AuthPass
		}
		return nil
	}},
	{Name: "geoip.maxmind_license_key", Ptr: func(c *gateonv1.GlobalConfig) *string {
		if g := c.GetGeoip(); g != nil {
			return &g.MaxmindLicenseKey
		}
		return nil
	}},
	// The repository URL is read like a database URL: a password in it is a
	// credential go-git sends, and the rest says which repository it is.
	{Name: "management.gitops.repository_url", URL: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if g := c.GetManagement().GetGitops(); g != nil {
			return &g.RepositoryUrl
		}
		return nil
	}},
	{Name: "management.gitops.auth_token", Destination: func(c *gateonv1.GlobalConfig) string {
		return urlOrigin(c.GetManagement().GetGitops().GetRepositoryUrl())
	}, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if g := c.GetManagement().GetGitops(); g != nil {
			return &g.AuthToken
		}
		return nil
	}},
	{Name: "waf.bot_management.secret_key", Ptr: func(c *gateonv1.GlobalConfig) *string {
		if b := c.GetWaf().GetBotManagement(); b != nil {
			return &b.SecretKey
		}
		return nil
	}},
	{Name: "security_advanced.deception.canary_token", Ptr: func(c *gateonv1.GlobalConfig) *string {
		if d := c.GetSecurityAdvanced().GetDeception(); d != nil {
			return &d.CanaryToken
		}
		return nil
	}},
	{Name: "security_advanced.pow.secret", Required: true, Ptr: func(c *gateonv1.GlobalConfig) *string {
		if p := c.GetSecurityAdvanced().GetPow(); p != nil {
			return &p.Secret
		}
		return nil
	}},
}
