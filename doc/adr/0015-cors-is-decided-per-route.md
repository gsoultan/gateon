# 15. CORS is decided per route, and a backend's own policy wins

Date: 2026-09-25

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves where cross-origin access is
decided, from the entrypoint to the route, and it lets every preflight reach the
deny decisions that used to be skipped for it.

## Context

Three things can have a CORS policy for a request: a `cors` (or `grpcweb`)
middleware on its route, the backend itself, and — for the management API —
`management.cors`. There was a fourth: `transform.GlobalCORS`, first in every
HTTP entrypoint's chain, before a route was chosen. It answered **every**
preflight itself, with a permissive credential-free policy, and on every other
request set `Access-Control-Allow-Origin` to the caller's origin before handing
the request on. It broke the other three:

1. **A route's own policy never saw a preflight.** A `cors` middleware that
   allows credentials for named origins was unusable for anything needing a
   preflight — a JSON `POST`, a `PUT`, an `Authorization` header — because
   browsers require `Access-Control-Allow-Credentials` on the preflight too.
   And the origins the route's policy refused got the permissive answer anyway.
2. **A backend's own policy was pre-empted twice.** Its preflights were answered
   without it, without credentials. Its responses left with two
   `Access-Control-Allow-Origin` values — the entrypoint's, then the backend's,
   added by the reverse proxy — and browsers refuse two. A backend that handles
   CORS itself, which is where most applications handle it, could not be used
   cross-origin behind the gateway at all.
3. **`management.cors` was pre-empted the same way** on any entrypoint that
   serves the management API.

It also answered preflights ahead of the entrypoint's deny decisions (IP and
user mitigation, the global geofence and honeypot, the connection limit), so a
preflight was the one request those never saw.

The permissive default itself is deliberate and older than this: commit
`28c2487` gave routes without a `cors` middleware a permissive preflight answer
to restore v1.5.0 behaviour, per route. Moving it to the entrypoint is what made
it pre-empt everything else.

## Decision

**The entrypoint answers no CORS.** Every request, preflights included, meets
the entrypoint's chain and then its route's.

**A route with a `cors` or `grpcweb` middleware is governed by it alone**, as
before; it now also receives its preflights.

**A route with neither gets `transform.DefaultCORS`**, in the same place in the
chain a route's own policy would sit (outside its security middlewares, so a
refusal made on the route is readable by the page that caused it). It decides
when the response is committed, from the finished headers:

- An answer that already carries `Access-Control-Allow-Origin` is the backend's
  own policy and goes out untouched — preflight or not, status and body intact.
- An actual response without one gets the permissive default: the caller's
  origin, `Vary: Origin`, the gRPC-web exposed headers. Never credentials.
- A preflight whose answer carries none is answered by the permissive default
  instead — the backend's answer, whatever its status, is no answer to the
  browser's question, and that is what the entrypoint used to give without
  asking. Its body is discarded rather than written into the 204, where
  net/http refuses it and the proxy's abort would close the connection.
- A request without `Origin` gets `Vary: Origin` and nothing else.

The management API keeps `management.cors`, which now sees its preflights.

## Consequences

- Credentialed CORS works on a route with a `cors` middleware, and a backend's
  own CORS reaches the browser unmodified. Backends that do not handle CORS see
  no change: the default still answers for them.
- **The default cannot tell "this backend does not do CORS" from "this backend
  refused this origin by leaving the header off".** Where a backend enforces an
  origin allowlist by omission, the default still grants the refused origin
  non-credentialed access, as the entrypoint did before. A route that must
  refuse origins attaches a `cors` middleware; `doc/upgrading.md` says so.
- Preflights now reach every deny decision on the entrypoint and the route —
  rate limits count them, the WAF inspects them — and on a route without a
  `cors` middleware they reach the backend, one extra request per preflight
  that browsers then cache for the answer's max age (86400 for the default).
- Refusals made before a route is chosen (mitigation, the global geofence and
  honeypot, the connection limit) no longer carry CORS headers; a browser
  reports them as a CORS failure rather than as a 403.
- Cost, measured against the entrypoint middleware it replaces: a request
  without `Origin` is slightly cheaper (55 ns vs 61 ns, same allocations); a
  cross-origin request on a route without a `cors` middleware allocates the
  commit-time writer (3 allocations vs 2, 113 ns vs 61 ns). Nothing changes on a
  route with its own policy.

## Related

- Invariant 7 in `CLAUDE.md` and `scripts/check-security-invariants.sh`: with
  nothing answering preflights ahead of the chain, it is the only thing between
  a preflight and the origin.
- ADR-0014, the other trust decision this review moved off client-supplied data.
