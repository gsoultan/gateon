# 94. A header only infrastructure sends is not taken from a client

Date: 2026-11-15

## Status

Accepted. `sec` drives (what a backend may believe about a request is a trust
boundary); `arch` co-signs where the boundary sits; `perf` challenges the cost
on every request.

## Context

Some request headers mean something only between a web framework and the
infrastructure in front of it:

- `X-Middleware-Subrequest` marks a request Next.js issued to itself, so its
  middleware is skipped. Sent by a client, it skips the authorization that
  middleware performs (CVE-2025-29927, CVSS 9.1).
- `X-Original-URL`, `X-Rewrite-URL`, `X-Original-URI` and `X-Override-URL` tell
  Symfony, Laravel, IIS URL Rewrite and nginx `auth_request` backends which
  path to serve.
- `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override` turn a POST
  into a DELETE on the backend.

Gateon forwarded all of them as the client wrote them. Everything it decides
-- which route matches, which IP filter, CEL policy, WAF exception, rate limit
and auth middleware apply -- is decided on the request line. A backend that
honours one of these headers then serves a different path or runs a different
method, one the gateway never matched, filtered or authorised. `/public` at
the gateway is `/admin` at the origin.

This is the defect `request.StripHeaderAliases` fixed for identity headers
(the Traefik CVE-2026-88879 class, found in the 2026-10-25 review): the
edge and the origin disagreeing about what a request says. That fix covered
the headers the gateway *sets*. These are headers the gateway never sets and
so never cleaned.

gwaf cannot own this. The header's value is harmless text; whether a client
may send it is a statement about who stands in front of the backend, which is
the embedder's (gwaf CLAUDE.md, Ownership and Policy tests). gwaf's CVE drill
records CVE-2025-29927 as `embedder` for that reason.

## Decision

**The entrypoint removes every header in `request.InternalHeaders` from every
request, before anything reads it**, in the canonical spelling and in the
underscore and dot aliases a header-folding backend reads as the same name.

- **Where:** `middleware.EntryPoint`, the first middleware of every listener's
  chain (HTTP, HTTP/3 and plaintext smart-TCP share `entrypointChain`). So no
  route, policy, forward-auth service, WebSocket upgrade or backend sees a
  client's copy, and there is one site to keep correct instead of one per
  outbound path.
- **No per-route switch.** A switch on the route would be a proto field, a
  migration and a dashboard control for something almost no install needs.
- **One exemption, global:** `GATEON_FORWARD_INTERNAL_HEADERS`, a
  comma-separated list of names to let through, read once at start. Empty on
  every tier. It exists for an API whose clients really do tunnel methods
  through POST. A name outside the list is ignored, so the variable cannot be
  used to forward anything else.
- **Counted:** `gateon_client_internal_headers_stripped_total{header}`. The
  label is the canonical name from the list, never what a client typed, so it
  is bounded at eight values.

### Cost

One pass over the request's header keys. A key that does not start with `X` or
is shorter than the shortest entry is skipped on two comparisons; the rest go
through one string switch. Measured at 95 ns and 0 allocations for an
eight-header request (`BenchmarkStripInternalHeaders`), against a request path
measured in tens of microseconds.

## Consequences

- **A client that sends a method-override header to a backend that honours it
  stops working on upgrade** until the operator names the header in
  `GATEON_FORWARD_INTERNAL_HEADERS`. This is in `doc/upgrading.md`. The counter
  shows whether any client sends one before and after.
- A gateway deployed *behind* another proxy that sets `X-Original-URL` for the
  backend (IIS ARR in front, say) loses that header too. The same variable
  restores it; the gateway cannot tell a proxy's header from a client's that
  the proxy passed along.
- The list is a list. A framework that invents a new internal header is not
  covered until it is added here, with a test.
