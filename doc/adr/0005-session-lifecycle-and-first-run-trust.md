# 5. Session lifecycle and first-run trust

Date: 2026-08-10

## Status

Accepted.

## Context

A review of the management plane's trust boundary found that two of its
assumptions were never enforced anywhere in the request path.

**A session outlived the account it belonged to.** `Manager.issueToken` minted a
24-hour PASETO carrying `id`, `username` and `role`. `Manager.VerifyToken`
checked the signature and the `exp`/`nbf` claims and returned. Nothing on an
authenticated request ever read the `users` table, so `SetUserDisabled`,
`DeleteUser`, `ChangePassword` and a role change through `UpsertUser` all wrote
to a row that no request path consulted. Disabling an account — the action an
operator takes when someone leaves or a credential is suspected stolen — set a
column and changed nothing. Demoting an administrator to viewer left them
holding a token that still asserted `role=admin` until it expired on its own.

**The gateway was open before it was configured.** On a first run
`inits.InitGlobalConfig` returns a nil `*auth.Manager`, because there is no
`global.json` yet and therefore no database and no PASETO key.
`CreateBaseHandler` captured that nil by value in `BaseHandlerDeps.Auth`, and
on finding no auth service it served the management API rather than refusing:

```go
if deps.Auth == nil || authInternal == nil {
    // No auth service available yet (e.g. first run)
    finalInternal.ServeHTTP(w, r)
}
```

The shipped default binds management to `0.0.0.0` with an allowlist of
`0.0.0.0/0` and `::/0`, so a fresh install on a routable address published
`/v1/routes`, `/v1/global`, `/v1/certificates`, `/v1/users` and
`/v1/config/export` to anyone who found it. Worse, `Setup` published the manager
it created only to `ApiService`; the HTTP handler kept the startup nil for the
life of the process, so completing setup did not close the hole. Only a restart
did.

Both are failures of the same kind: a security decision expressed as data that
no code on the enforcing path reads.

## Decision

**Bind tokens to the account state they were issued against.** A token carries
an `sb` claim: a digest over the user's password hash, role and disabled flag.
`VerifyToken` recomputes it and refuses on mismatch. Changing the password, the
role or the disabled flag changes an input, so all four revocation events fall
out of one mechanism, and a deleted row has no binding to match at all.

This was chosen over the two obvious alternatives:

- *A revocation list.* Another structure to bound, expire and replicate, and it
  only revokes what is explicitly added — a role change would have to remember
  to add itself.
- *A `token_version` column.* Correct, but requires a migration and a call to
  bump it at every mutation site; forgetting one fails open. Deriving the value
  from the columns that already exist means a new security-relevant column is
  added to the digest once and every caller inherits it.

The binding is cached per user id and invalidated on mutation, so the steady
state is a map read rather than a database round trip. The cache is keyed by the
id inside an already-decrypted PASETO, so only tokens this gateway minted can
create entries — it is bounded by the number of real accounts, not by anything a
caller can invent. Token lifetime drops from 24 hours to 8.

**Fail closed when there is no auth service, and make the reference swappable.**
`auth.Holder` is an atomically-swappable `auth.Service` installed once at
startup and shared by every consumer. `Setup` swaps the real `Manager` into it,
so enforcement begins immediately rather than at the next restart. Every method
denies while empty, and `VerifyToken` in particular returns `ErrUnavailable`
rather than a nil error. The base handler serves only setup and health endpoints
until a service exists and answers 503 for everything else.

`auth.Available(Service) bool` replaces `== nil` at call sites, because a Holder
is never nil but is not usable until Setup has run.

**Leave the management bind default alone, and say what it means.** Binding to
loopback by default would be safer on a bare-metal host and would break every
container deployment, where a process on loopback is unreachable through a
published port. Since neither value is safe everywhere and the gateway cannot
know which it is in, startup logs the exposure explicitly when the bind is a
wildcard and the allowlist constrains nothing.

## Consequences

Sessions now end when the account changes, which is what operators already
believed was happening. Users are logged out by a password change or a role
change — correct, and worth noting in release notes because it is a visible
behaviour change.

Tokens issued before this change carry no `sb` claim and are refused. Everyone
is logged out once on upgrade. Grandfathering them in would have made the check
optional for exactly the tokens minted while the gateway was vulnerable.

The binding cache is per process. A multi-instance deployment sharing one
database will not see another instance's invalidation until its own cache entry
is evicted or that instance restarts; revocation is immediate only on the
instance that performed the mutation. Closing that requires propagating
invalidations over the existing Redis channel, which is deliberately not in this
change.

> **Amended 2026-08-14.** As written above, "until its own cache entry is
> evicted" was doing more work than it could support: entries had no expiry, so
> on a sibling instance a revoked session stayed valid indefinitely, not merely
> for a while. Cached bindings now carry a TTL (`DefaultBindingTTL`, 30s,
> overridable with `GATEON_SESSION_BINDING_TTL`), and an expired entry is
> reported as absent so the next verify reloads from the database.
>
> This bounds the window rather than removing it, and it is deliberately the
> floor rather than the finished design. Redis propagation would cut the delay to
> a round trip, but pub/sub is at-most-once: a dropped message or a broker outage
> puts the unbounded staleness straight back. An expiry needs no broker and
> cannot silently stop working, so it is the guarantee, and propagation — when it
> lands — is a latency optimisation on top of it, not a replacement for it.
>
> Wiring Redis into `auth.Manager` also adds a dependency to a constructor on the
> trust boundary, which needs its own ADR and an `arch`/`sec` co-sign rather than
> being folded into a cache fix.

A first run now refuses the management API until setup completes. An operator
automating a fresh install against `/v1/routes` before creating an administrator
will get 503 instead of success; the fix is to call `/v1/setup` first, which was
always the intended order.
