// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package storedsecret

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Secret is one credential field of a list element.
type Secret struct {
	Name string
	Ptr  *string
}

// Element is one element of a list whose elements carry credentials.
//
// ID is the element's identity: a stored secret is matched to an element of an
// update by it and by nothing else. Position is not an identity -- a reordered
// or shortened list would hand one element's credential to another -- and
// neither is a name, which the operator is free to change.
type Element struct {
	ID   *string
	Name string
	Type string
	// Destination is where the element's secrets are sent, when that depends
	// on the element; "" when it does not.
	Destination string
	Secrets     []Secret
}

// List is a repeated field whose elements carry credentials.
type List struct {
	// Name is the list's path in the proto.
	Name     string
	Elements func(c *gateonv1.GlobalConfig) []Element
}

// Lists lists every repeated field of a GlobalConfig whose elements carry
// credentials.
func Lists() []List { return lists }

var lists = []List{
	{Name: "security_advanced.ip_reputation.integrations", Elements: integrations},
	{Name: "alerting.dispatchers", Elements: dispatchers},
}

// integrations are the IP-reputation integrations. The provider, and so the
// address the API key goes to, is the integration's type.
func integrations(c *gateonv1.GlobalConfig) []Element {
	list := c.GetSecurityAdvanced().GetIpReputation().GetIntegrations()
	out := make([]Element, 0, len(list))
	for _, in := range list {
		if in == nil {
			continue
		}
		out = append(out, Element{
			ID: &in.Id, Name: in.Name, Type: in.Type, Destination: in.Type,
			Secrets: []Secret{{Name: "api_key", Ptr: &in.ApiKey}},
		})
	}
	return out
}

// dispatchers are the alert dispatchers. A Slack or Discord incoming-webhook
// URL is the credential itself, and a Telegram token goes to Telegram's fixed
// address, so neither is bound to anything else in the element.
func dispatchers(c *gateonv1.GlobalConfig) []Element {
	list := c.GetAlerting().GetDispatchers()
	out := make([]Element, 0, len(list))
	for _, d := range list {
		if d == nil {
			continue
		}
		out = append(out, Element{
			ID: &d.Id, Name: d.Name, Type: d.Type,
			Secrets: []Secret{
				{Name: "webhook_url", Ptr: &d.WebhookUrl},
				{Name: "telegram_bot_token", Ptr: &d.TelegramBotToken},
			},
		})
	}
	return out
}

// AssignIDs gives every credential-carrying list element that has no id one,
// so that its stored secret can be kept by the next save.
//
// An element without an id cannot be matched to its stored secret, and a
// configuration written by hand or by an API client need not carry ids. The id
// is derived from the element's list, position, type and name, so it is the
// same on every start until a save persists it; the position only names the
// element once, and matching never uses it. Elements that have an id keep it.
func AssignIDs(c *gateonv1.GlobalConfig) {
	for _, l := range lists {
		for i, e := range l.Elements(c) {
			if *e.ID == "" {
				*e.ID = derivedID(l.Name, i, e)
			}
		}
	}
}

func derivedID(list string, position int, e Element) string {
	sum := sha256.Sum256([]byte(list + "\x00" + strconv.Itoa(position) + "\x00" + e.Type + "\x00" + e.Name))
	return "gen-" + hex.EncodeToString(sum[:6])
}

// databaseAddress is where a database password is sent: the server, not the
// account or the database on it.
func databaseAddress(d *gateonv1.DatabaseConfig) string {
	if d == nil {
		return ""
	}
	return strings.ToLower(d.GetDriver()) + "|" + strings.ToLower(strings.TrimSpace(d.GetHost())) + "|" +
		strconv.Itoa(int(d.GetPort()))
}

// urlOrigin is the scheme and host a URL sends its credentials to, or the
// whole value when it is not a URL with a host. Any userinfo is dropped by
// hand before parsing: a masked one holds Sentinel, which url.Parse rejects,
// and the answer must not depend on whether the password was restored yet.
func urlOrigin(raw string) string {
	v := strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(v, "://")
	if !ok {
		return v
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	host := rest[:end]
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Host == "" {
		return v
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
