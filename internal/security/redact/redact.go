// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package redact removes credentials from gateway-observed data before it is
// stored or leaves the process (ADR 0060).
//
// The gateway records what it sees -- traces, threats, the WAF audit log, alert
// payloads -- and what it sees is other people's credentials: an app's session
// cookie, a bearer token, an API key in a query string, a password in a login
// form, an OAuth authorization code. Those records are read from the
// dashboard, kept for days, archived for months and posted to third-party
// webhooks. None of that needs the credential's value; triage needs to know
// that one was there, where, and what everything else around it said.
//
// Everything here decides by name and by shape, and errs towards masking: a
// value hidden that did not need hiding costs the operator a "[REDACTED]" in a
// trace, and the reverse is a credential in a webhook.
package redact

import (
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/security/secretmask"
)

// Mask is what a credential's value is replaced with. The same marker the
// header redaction has always written, so one string means one thing in every
// record.
const Mask = "[REDACTED]"

// credentialParams are parameter and field names that carry a credential but
// that secretmask.IsCredentialName's fragments do not catch: the OAuth 2.0 /
// OIDC authorization response (code, and state, which binds it to the browser
// that asked), the short password spellings, one-time codes, a SAS or presigned
// URL signature, a CAS ticket and a SAML assertion. Matched exactly and
// lower-cased: as fragments, "code" and "state" would mask "zipcode" and
// "statement".
var credentialParams = []string{"code", "state", "pass", "pwd", "pin", "otp", "sig", "ticket", "samlresponse"}

// IsCredentialParam reports whether a query parameter, form field or JSON key
// of this name carries a credential. It is secretmask.IsCredentialName -- the
// vocabulary the configuration masking uses -- plus credentialParams.
func IsCredentialParam(name string) bool {
	if name == "" {
		return false
	}
	return secretmask.IsCredentialName(name) || equalsAnyFold(name, credentialParams)
}

// publicHeaders are header names IsCredentialName matches that carry no
// credential: a challenge saying which credential is wanted, and the
// WebSocket handshake's nonce and its digest. Masking them hides triage data
// and protects nothing.
var publicHeaders = []string{
	"www-authenticate", "proxy-authenticate",
	"sec-websocket-key", "sec-websocket-accept", "sec-websocket-protocol",
}

// IsCredentialHeader reports whether a header of this name carries a
// credential: Authorization, Cookie and Set-Cookie, and anything named like a
// key, token, secret, session or signature (X-Api-Key, X-Auth-Token,
// X-Amz-Security-Token, Private-Token, ...).
func IsCredentialHeader(name string) bool {
	return secretmask.IsCredentialName(name) && !equalsAnyFold(name, publicHeaders)
}

// challengeHeaders name the credential a server wants, and carry none of the
// client's; a challenge's parameters (realm=, authorization_uri=) follow the
// scheme name the way a credential would.
var challengeHeaders = []string{"www-authenticate", "proxy-authenticate"}

// HeaderValue returns the value of a header whose name does not say it carries
// a credential, with every credential in it masked by its shape: a JSON Web
// Token, a gateway API token or a PASETO token (the prefix kept), the
// credentials after Bearer or Basic, and a value that is wholly an encoded
// Authorization value -- what IsCredentialValue finds in a query value, found
// in a header. The rest of a structured value -- Forwarded's for= and proto=,
// a list's other members -- stays readable. A name says nothing about a value:
// AWS ALB's X-Amzn-Oidc-Data is a signed user token, and any proxy may forward
// one under a name of its own (review 3, F4).
//
// It returns value itself, allocating nothing, when there is nothing to mask:
// it runs for every header of every trace and threat the store keeps.
func HeaderValue(name, value string) string {
	if equalsAnyFold(name, challengeHeaders) {
		return value
	}
	var spans []span
	spans = schemeSpans(value, spans)
	spans = tokenSpans(value, spans)
	if len(spans) == 0 {
		if v := strings.TrimLeft(value, " \t"); IsCredentialValue(v) {
			return value[:len(value)-len(v)] + Mask
		}
	}
	return apply(value, spans)
}

// uriHeaders are the headers whose value is a URI by definition.
var uriHeaders = []string{"referer", "location", "content-location"}

// IsURIHeader reports whether a header's value is a URI whose query string may
// carry a credential: Referer and Location (an OIDC callback's redirect names
// the authorization code), and the X-Forwarded-Uri / X-Original-Url family.
func IsURIHeader(name string) bool {
	return equalsAnyFold(name, uriHeaders) || indexFold(name, "uri") >= 0 || indexFold(name, "url") >= 0
}

// equalsAnyFold reports whether name, trimmed, is one of names without regard
// to case. It allocates nothing: these run for every header the store keeps.
func equalsAnyFold(name string, names []string) bool {
	n := strings.TrimSpace(name)
	for _, c := range names {
		if strings.EqualFold(n, c) {
			return true
		}
	}
	return false
}

// span is a byte range of a string to be replaced by repl.
type span struct {
	start, end int
	repl       string
}

// apply returns s with every span replaced. Spans may overlap and arrive in
// any order; an overlap is merged into the span that starts first, so a token
// found by two scanners is masked once.
func apply(s string, spans []span) string {
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for i := 0; i < len(spans); i++ {
		cur := spans[i]
		for i+1 < len(spans) && spans[i+1].start < cur.end {
			cur.end = max(cur.end, spans[i+1].end)
			i++
		}
		b.WriteString(s[pos:cur.start])
		b.WriteString(cur.repl)
		pos = cur.end
	}
	b.WriteString(s[pos:])
	return b.String()
}
