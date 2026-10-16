# 71. A request cannot exempt its own body from the WAF

Date: 2026-10-16

## Status

Accepted.

## Context

git's smart-HTTP protocol sends a packfile as the request body of a push: binary,
and routinely larger than the WAF body limit. Refusing it as uninspectable would
break every git host behind the gateway, so the WAF has long skipped the body of
a request that looks like git traffic.

What "looks like git traffic" meant was a `Content-Type` of
`application/x-git-upload-pack-request` or `application/x-git-receive-pack-request`,
or a path ending in `/git-upload-pack` or `/git-receive-pack`. Both are written by
the client. An earlier fix stopped the same signals from skipping the whole
middleware, and gated the remaining body skip on a reputation score above 90.
That gate admits everyone it was meant to filter: a client the gateway has not
seen scores 100, the top of the scale.

So any client could put a SQL or command injection in a body, add git's
`Content-Type`, and reach the backend uninspected, on every route behind a WAF.
The oversize check was skipped with the body, so the body could be any size. A
backend that parses a body without checking its `Content-Type` (a Go handler
calling `json.NewDecoder(r.Body)`, PHP reading `php://input`) acts on it.
Reproduced: the same JSON body was refused as `application/json` and forwarded
with git's `Content-Type`, and so was a 20 MiB body.

## Decision

**The body exemption is the operator's to grant, per route or per deployment, and
is off by default.**

- A route WAF reads `git_smart_http` (`"true"` or `"1"`). The dashboard shows it
  as *This route hosts git* on the WAF middleware.
- `GATEON_WAF_GIT_SMART_HTTP` is the deployment default. It is the only path for
  the gateway-wide WAF, whose settings proto has no such field, and the fallback
  for a route that leaves the key unset. A route's explicit value wins in either
  direction.
- Where it is on, the old conditions still apply on top: a git-looking request
  from a client above 90 has its body left unread. The request line, query and
  headers are inspected as before.
- The switch is part of the WAF config fingerprint and the global WAF cache key,
  so configs that differ only in it never share an engine.

The switch is Operational, like `audit_only` and `fail_open` on a route WAF
(ADR 0064): an operator can already weaken a route's WAF, and this does not move
that line. What it removes is a client's ability to do it.

## Consequences

- A git server behind a WAF route refuses pushes larger than the body limit with
  `403` until the operator turns the switch on. `doc/upgrading.md` says so.
- On a route with the switch on, a client can still send an uninspected body by
  naming git. That is the cost of hosting git behind the WAF, and it is now
  confined to routes where the operator accepted it. Inspecting the pkt-line
  preamble of a push instead of nothing would narrow it further; that needs a
  packfile-aware reader and is not part of this change.
