# 16. Per-route state is keyed by the route's ID; its name is a label

Date: 2026-09-25

## Status

Accepted. `arch`, with `sec` consulted: one of the three stores involved is a
cache, and a cache keyed by something two routes can share is a data leak
between them.

## Context

A route has an ID, which the store keys it by and which is unique, and an
optional name. `router.RouteLabel` is the name, or the ID when there is no
name, and it was handed to every middleware as *the* route — for what a person
reads (metric labels, access logs, threat records) and for what the gateway
keeps per route. Nothing made names unique: not the API, not config import, and
not the Kubernetes controller, which gave every path of an Ingress rule, and
every match and host of an HTTPRoute rule, the rule's name.

So routes that shared a name shared state:

- **One circuit breaker.** A failing backend behind one route opened the
  circuit, and the other route, whose backend was healthy, answered 503.
- **Redis cache entries.** The Redis backend is shared by every route on every
  instance, and its keys carried the label, so a route answered from another
  route's cached responses for the same method, host and path. Two routes that
  differ only by a header — one per tenant — are exactly that.

A third store was shared by every route regardless of name: the Redis rate
limiter kept one window per client, `ratelimit:v2:<client>`, so a client's
requests to one route counted against every other route's limit, and a route
with two Redis limiters counted each request twice.

## Decision

**State is kept under the route's ID.** `Factory.SetRouteKey` gives a factory
the route's ID and `Create` hands it to every middleware as
`kind.RouteStateKey`, beside the label in `kind.RouteIDKey`. A middleware's own
config cannot set it. The circuit breaker, the cache key and the Redis rate
limiter use it; the rate limiter's window is also keyed by the middleware's ID
(`kind.MiddlewareIDKey`), so two limiters on one route count separately.
Metrics, logs and threat records keep the label.

**Names are unique.** Saving a route whose label another route already has is
refused (`route.ErrRouteNameTaken`). The Kubernetes controller names routes as
uniquely as it identifies them. Routes that already share a name — from before,
or from a config file — keep working with separate state, and the proxy cache
logs each shared name once per change, because their metrics are still reported
together.

**A rename starts a new breaker** under the new name, as it did when the label
was the key, and the old name's gauge goes.

**The OIDC cookies stay keyed by label.** Two routes sharing a name share the
state, origin and session cookie names, but each verifies a session against its
own issuer and client, so that is no bypass; re-keying would sign every OIDC
user out on upgrade to fix a case that unique names now prevent.

## Consequences

- Breakers, cached responses and Redis rate-limit windows are per route. Redis
  cache and rate-limit keys change format, so both start cold on upgrade.
- A client that was being throttled by its traffic to other routes now gets
  each route's configured limit.
- Metrics of Kubernetes-generated routes move to the new, distinct names.
- Import of a configuration with duplicate route names imports the first and
  reports the others.

## Related

- `doc/upgrading.md`, "Route names are unique, and per-route state is kept per
  route".
