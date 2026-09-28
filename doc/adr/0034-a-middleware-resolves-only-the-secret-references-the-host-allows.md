# 34. A middleware resolves only the secret references the host allows

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary. What an operator
who can write a middleware may make the gateway read was, in effect, everything;
it is now what the host has named.

## Context

A middleware's configuration is written by an operator, not only an
administrator, and the factory resolves `$env:`, `$vault:` and `$aws-sm:`
references in every field it builds (`config.ResolveSecretStrict`). Nothing
constrained which references, or which fields. So an operator could:

- put `$env:GATEON_ENCRYPTION_KEY` (or a database password, or a session key
  held as a reference) in a headers middleware's `set_response_X-Anything` and
  read the resolved value back in the response; or
- put the same reference in a secret field, such as an OAuth2 `client_secret`,
  and point that middleware's `introspection_url` at a server they run, so the
  gateway sends the secret there.

Both are an operator-to-admin escalation, and both defeat ADR 0033: a secret
held as a reference was still reachable, just not read through the config API.
Making middleware secrets write-only closed the read; it did not close the
resolve.

## Decision

The factory refuses to build a middleware whose field holds a secret reference
unless **both** hold, and a refused build is served the refusal any
un-buildable security middleware is (ADR 0033), so the boundary fails closed:

- **The field holds a secret.** A reference is honoured only in a field
  classified as a secret (`mwsecret.IsSecretField`): a scalar secret, a
  basic-auth user list, an API key, or a header or query value under a
  credential name. In any other field a reference is refused, because its
  resolved value would only be echoed to the client -- the exfiltration path.
- **The host allow-listed the reference.** `GATEON_MIDDLEWARE_SECRET_REFS` lists
  the exact references (whole strings, not prefixes) a middleware may resolve.
  It is read from the environment, which the management API cannot write, so the
  operator who writes the middleware cannot also grant themselves the reference.
  Unset, no middleware field may resolve any reference.

The allow-list is a security control, not a resource knob: its value does not
scale with a tier, so it has no `TierDefaults` entry, like
`GATEON_MITIGATION_ALLOWLIST` and `GATEON_PREVIOUS_SESSION_KEY`.

The global configuration's own secret fields are unchanged: only an
administrator writes them, so their references are the administrator's to name
and are resolved as before.

## Consequences

- An install that used `$env:` or `$vault:` in a middleware field must list that
  reference in `GATEON_MIDDLEWARE_SECRET_REFS`, or put the value in directly.
  Until it does, the route serves the security refusal, and the build error
  names the reference and the variable. This is a behaviour change on upgrade.
- A literal or `enc:`-encrypted secret in a middleware field is not a reference
  and is unaffected.
- The exfiltration-by-header path is closed outright (references are refused in
  non-secret fields); the exfiltration-by-destination path is closed for every
  reference the host did not name.
- The residues: an operator can still send a *literal* secret they already know
  to a destination they choose, and can attach a middleware to a route whose
  backend they run (recorded against a later route-graph check). This ADR
  constrains only what the gateway *resolves* on their behalf.
