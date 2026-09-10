# 12. Session revocation propagates over Redis, but expiry is what guarantees it

Date: 2026-09-10

## Status

Accepted. Co-signed `arch` ↔ `sec`: it adds an input to the management plane's
trust boundary. Supersedes the deferral recorded in
[ADR 0005](0005-session-lifecycle-and-first-run-trust.md)'s amendment.

## Context

A session token carries an `sb` claim — a digest over the account's password
hash, role and disabled flag — and `VerifyToken` recomputes it on every request.
Recomputing means reading the account, so the binding is cached per user id, and
mutations invalidate the entry.

That invalidation is local. On a multi-instance deployment sharing one database,
an operator disabling an account ends its sessions immediately on the instance
that handled the request and nowhere else. ADR 0005 shipped with no expiry at
all, which made "nowhere else" mean *indefinitely*; the 2026-08-14 amendment
added `DefaultBindingTTL` (30s, `GATEON_SESSION_BINDING_TTL`) so a sibling
converges when its entry expires.

Thirty seconds is a bounded window, not a closed one, and
`doc/security-posture.md` has been carrying it as a known limitation. It is the
constraint that stops gateon claiming horizontal scale honestly: disabling a
compromised account is exactly the operation an operator expects to take effect
now, on every node, and "within thirty seconds on the others" is a different
promise.

## Decision

**Propagate invalidations over the Redis channel that already exists, and keep
the TTL as the guarantee.**

The ordering matters and is the whole design. Redis pub/sub is at-most-once:
there is no acknowledgement, no redelivery, and a subscriber that is
disconnected during a publish never learns the message existed. A broker outage,
a network partition or a slow consumer silently drops invalidations. If
propagation were the mechanism, every one of those failures would restore
exactly the unbounded staleness ADR 0005 shipped with — and it would do so
invisibly, because nothing on the request path can tell a message that was never
sent from one that was never needed.

So the expiry stays, unchanged, and does the work it does today. Propagation
sits on top and turns the common case from "up to 30 seconds" into "one Redis
round trip". When Redis is absent, unreachable or dropping messages, behaviour
is **exactly what it is today** — which is the property that makes this safe to
add rather than a new thing that can break.

### The listener may only invalidate, never populate

A remote message can drop a cached binding. It cannot create or update one.

This is what makes a new input to the trust boundary acceptable, and it is a
structural property rather than a promise: the only method exposed to the
listener is `InvalidateBinding(id)`, which deletes a map entry. There is no path
from a received message to `bindingCache.put`.

The consequence is that the worst an attacker who can publish to the channel can
achieve is forcing cache misses — extra database reads, and users' bindings
re-read rather than served warm. That is a denial-of-service pressure on the
database, bounded by the account count and the same reads that happen naturally
at TTL expiry. It is **not** an authentication bypass, because dropping a cached
binding makes the next verify *stricter* (it re-reads the account), never
weaker. A control that can only fail toward more checking is one we can accept
an untrusted input into; the inverse would need the channel authenticated first.

Redis is already trusted with the response cache, distributed rate-limit
counters and the ACME certificate cache, so this adds no new component to the
deployment — but it does add a new *kind* of authority, and the paragraph above
is why it is bounded.

### No Redis dependency in `internal/auth`

ADR 0005 deferred this partly because wiring Redis into `auth.Manager` adds a
dependency to a constructor that sits on the trust boundary. That objection is
answered rather than overridden: `internal/auth` defines a one-method publisher
interface and knows nothing about Redis. The implementation lives in
`internal/server`, where the client already is, and is installed after
construction the same way `SetCache` installs the ACME cache. `auth.NewManager`
is unchanged, and the auth package's test suite needs no broker.

### One channel, not a second one

The message rides `gateon:config:invalidation`, the channel that already carries
route, TLS and WAF invalidations, with a new `session` type. A second channel
would mean a second subscriber goroutine, a second reconnect path and a second
thing to notice had stopped working.

## Where it lives

- `internal/auth/revocation.go` — the publisher interface, and
  `InvalidateBinding` as the local-only entry point for remote events.
- `internal/auth/manager.go` — `revokeSessions` publishes after invalidating.
- `internal/server/distributed_invalidator.go` — the Redis publisher and the
  `session` case in the listener.

## Consequences

Revocation on a healthy multi-instance deployment is a Redis round trip rather
than up to 30 seconds. `doc/security-posture.md`'s known limitation narrows
accordingly, and says what it degrades to.

**The degraded case is the documented one, not a failure.** With no Redis
configured — the default, and every single-instance deployment — nothing
changes: the publisher is nil and the TTL is the whole mechanism, as it is
today.

Node identity moves from the hostname to a per-process value. The existing
listener skips messages whose `node_id` matches its own, and derived that from
`os.Hostname()` — so two instances on one host, which is an ordinary container
arrangement, discarded each other's invalidations as self-broadcast. That was
already true for route, TLS and WAF invalidation and is fixed here for all four.

A publish failure is not surfaced to the caller. The mutation has already
succeeded and been invalidated locally; the remote effect is the optimisation,
and failing an operator's "disable this account" because a broker was down would
be the wrong trade when the TTL still bounds the result.
