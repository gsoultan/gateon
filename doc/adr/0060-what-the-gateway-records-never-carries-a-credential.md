# 60. What the gateway records never carries a credential

Date: 2026-10-04

## Status

Accepted. `sec` with `obs`: it changes what traces, threats, the WAF audit log
and alert payloads contain. `perf` for where the work runs (off the request
path), `mem` for the body bound.

## Context

ADR 0041 and ADR 0051 keep the dashboard's own credentials out of the data
plane. They say nothing about the credentials of the applications behind the
gateway, which the gateway sees on every request and writes into everything
it records. The 2026-10-04 review and a probe of the built binary found:

- **Query strings.** A trace's `RequestURI`, a threat's, the alerts built from
  it, the SIEM event and correlation signal built from that, and the trace
  archive kept `?api_key=`, `?access_token=`, `?password=`, an OAuth `?code=`
  and `?state=` as sent. So did the `Referer` of a trace and the `Location` of
  a redirect (an OIDC callback's names the code).
- **Bodies.** A debugger capture stored both bodies whole -- a login form's
  password, the token response to it -- and a threat copied them; the generic
  webhook posted the whole threat record to whatever URL was configured. (On
  the built binary the debugger capture never reached a trace at all: the
  metrics middleware looked for it in the request context, and the debugger
  puts it on the request state whenever there is one, which is always. Fixed
  here, which makes the body redaction live rather than latent.)
- **The WAF audit log** copies up to 256 bytes of what a rule matched. An SQL
  injection in a cookie put the cookie in the log; a data-leak rule put the
  AWS key it found there.
- Header redaction worked from a list of seventeen names; `X-Session-Token`,
  `X-Amz-Signature` and every vendor header nobody listed were stored as sent.

## Decision

**One vocabulary, one package.** `internal/security/redact` decides what is a
credential, by name and by shape, and masks it with `[REDACTED]`:

- `IsCredentialParam` -- a query parameter, form field or JSON key:
  `secretmask.IsCredentialName` (the vocabulary configuration masking already
  uses, ADR 0033: anything containing token, secret, passw, key, auth, session,
  credential, signature, bearer, jwt) plus `code`, `state`, `pass`, `pwd`,
  `pin`, `otp`, `sig`, `ticket`, `samlresponse` matched exactly.
- `IsCredentialHeader` -- the same, less the challenge and handshake headers
  that only look like one (`WWW-Authenticate`, `Sec-WebSocket-Key`, ...).
- `IsCredentialValue` -- a value that is a credential under any name: a JWT,
  a `gateon_tok_` token, a PASETO token, an encoded `Bearer`/`Basic` value.
- `URI` masks the values of credential parameters and keeps their names,
  every other parameter and the path, byte for byte.
- `Text` masks credential JSON members, `name=value` pairs, multipart parts,
  quoted credential header lines, `Bearer`/`Basic` credentials, JWTs and
  gateway/PASETO tokens anywhere in a text.
- `Body` is `Text` over a body cut to 64 KiB. A body that is not text --
  compressed, protobuf, binary -- cannot be shown to be free of a credential
  and is replaced by a note of its length.

**Where it runs.** Every trace and every threat passes through the telemetry
store's loop before anything stores, archives, broadcasts, alerts on, ships or
correlates it; that is where they are cleaned (`processTrace`,
`normalizeThreatHeaders`), off the request path. The WAF audit log writes
directly, so it applies `URI` to its request line and withholds `matched_bytes`
(keeping rule, target, key, offset and length, and saying
`matched_bytes_withheld`) when the match was in a credential header, a
URI-valued header or request URI whose query carries one, an argument named or
shaped like one, a raw body quoting one, or came from a data-leak rule. The
access log records the path without its query and is unchanged.

*Amended 2026-10-05 (review 3).* Two places did not do what this says. A
header whose name is not a credential's was kept as sent whatever its value,
so AWS ALB's `X-Amzn-Oidc-Data` JWT, a `gateon_tok_` token under `X-Upstream`
and `Bearer ...` in a neutral header reached traces, threats and the webhook's
`requestHeaders`. `HeaderValue` now masks such a value by shape -- the shapes
`IsCredentialValue` finds in a query value, plus `Bearer`/`Basic` credentials --
keeping the rest of a structured value (`Forwarded: for=...;by=[REDACTED]`) and
leaving a challenge (`WWW-Authenticate`) alone; `RedactHeaders` allocates once
per block instead of five times, at about 11% more CPU. And the CORS middleware
alerted on its own unredacted copy of a violation on the request path; it now
only records it.

**The generic webhook sends no bodies.** The fields stay in the payload,
empty. There is no setting to send them: the threat id in the payload leads to
the dashboard, which holds them (redacted), and a webhook is usually a third
party. Slack, Discord and Telegram never sent bodies.

**The debugger is bounded by what is kept**: its capture is at most 64 KiB per
body whatever `max_body_size` says; a smaller value still applies.

## Consequences

- No stored trace, stored threat, WAF audit line, alert payload or access-log
  line carries the value of a credential the gateway can recognise by name or
  shape. `TestNoCredentialLeavesTheGatewayInWhatItRecords` proves it on the
  built binary.
- Masking errs towards masking. Parameters such as `keyword`, `author` or
  `session_count` are masked too; `X-Api-Key-Id` is now masked in a trace.
  Their names stay readable.
- Not covered: a credential under a name and in a shape that give nothing
  away (`?x=<opaque random string>`, `X-Upstream: <opaque token>`), one in a URL
  path (`/reset/<token>`), one inside an encoding redaction does not read
  (base64, a percent-encoded JSON document), and a value in an HTML attribute
  (`<input name="csrf_token" value="...">`).
- Threat-detail analysis that read attack payloads out of a stored query
  string sees `[REDACTED]` where the payload sat in a credential parameter.
  The WAF saw the request unredacted and decided on it.
- Records written before this change are not rewritten; they age out with
  trace and threat retention.
- A WAF match inside a cookie or the joined arguments is withheld by target.
  gwaf v0.6.2 did not report either collection for gateon's requests (a
  cookie match arrives as the `Cookie` header), so that handling is defensive.
- Cost: none on the request path except the debugger's bound. In the store's
  loop, `URI` and `Text` return their input without allocating when there is
  nothing to mask, and classifying a header name allocates nothing
  (`IsCredentialName` stopped lower-casing a copy to make that true); tests pin
  both.
