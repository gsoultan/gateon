# 6. Transport-neutral authorization for the management API

Date: 2026-08-14

## Status

Accepted. Extends ADR 0005, which settled *authentication* for the management
plane; this one settles *authorization* across the transports that plane is
served on.

## Context

The management API is reachable over three transports, and all three end at the
same `*api.ApiService` methods:

1. **REST**, registered on a `http.ServeMux` by `handlers.RegisterRESTHandlers`.
2. **ConnectRPC**, mounted on the same mux via `api.NewConnectHandler`.
3. **gRPC and gRPC-Web**, served by a `grpc.Server` that
   `Server.HandleProxyOrLocal` selects on `Content-Type` *before* the mux is
   consulted at all (`internal/server/proxy.go`).

Authorization existed on exactly one of them. It was written as

```go
func RequirePermission(w http.ResponseWriter, r *http.Request, action auth.Action, resource auth.Resource) bool
```

with roughly forty call sites, every one inside `internal/server/handlers/`.
That signature cannot be called from a ConnectRPC or gRPC handler — there is no
`http.ResponseWriter` and no `*http.Request` at that layer — so the other two
transports enforced nothing. `internal/api/` carried two ad-hoc checks in total
(`users.go`, self-or-admin on `ChangePassword` and `requireAdmin` on the three
user RPCs) and no others.

Authentication was never the gap. `base_handler_auth.go` names both `/v1/` and
`/gateon.v1.` in every predicate, so all three transports sit behind
`PasetoAuth` and arrive with `*auth.Claims` on the context. Nothing read them.

Two concrete failures followed:

- A `viewer` was refused by `POST /v1/diagnostics/mitigate` and accepted by
  `/gateon.v1.ApiService/MitigateThreat`. Same service method, opposite answer.
  The same held for `RemoveMitigatedThreat`, which lifts a block a mitigation
  placed, and `ApplyRecommendation`, which writes configuration.

- Worse, because the gRPC server had the *whole* service registered and no
  interceptor, any authenticated principal of any role could reach every RPC by
  sending `Content-Type: application/grpc-web`. Privilege escalation selectable
  by a request header.

The second is the one that matters structurally. The first was a migration
losing a check; the second was a transport that never had one.

This was not a coding mistake so much as a placement mistake. Authorization was
put in a *transport adapter* rather than at the boundary the adapters share, so
"add a transport" silently meant "opt out of authorization". The ongoing
REST → Connect migration was therefore subtracting enforcement as it advanced,
and nothing failed to compile when it did.

## Decision

**Authorization for the management API is a property of the procedure, not of
the transport that carried it.**

One table, `apiPermissions` in `internal/server/api_rbac.go`, maps every
`ApiService` procedure to the permission it requires. Two interceptors apply it:

- `NewConnectRBACInterceptor()` — a `connect.UnaryInterceptorFunc` on the
  ConnectRPC handler.
- `NewGRPCRBACInterceptor()` — a `grpc.UnaryServerInterceptor` on the
  `grpc.Server`. `ApiService` declares no streaming RPCs, so a unary
  interceptor covers all of it; adding one would require a stream interceptor
  and this ADR to be revisited.

Both resolve to the same `authorizeProcedure`, which returns a sentinel error
that each interceptor renders in its own code space
(`connect.CodePermissionDenied` / `codes.PermissionDenied`).

Three rules make it hold:

1. **Unmapped procedures are denied**, on both transports. A new RPC is
   unreachable until someone states what it requires.
2. **The table is exhaustive by test.**
   `TestAPIPermissions_CoversEveryProcedure` reflects over the generated
   `gateonv1connect.ApiServiceHandler` interface and fails if any declared RPC
   lacks an entry, or if any entry names an RPC that no longer exists. Rule 1
   makes a missing entry safe; rule 2 makes it *loud*, at the moment the proto
   changes rather than when a user reports a 403.
3. **Each entry mirrors its REST twin.** The permission is not invented per
   transport; it is copied from the `RequirePermission` call on the
   corresponding `/v1/` route, so the three transports answer identically.

REST keeps `RequirePermission` rather than moving behind the same interceptor.
Rewriting forty handlers to close a hole in the other two is a larger change
with more ways to go wrong, and the table is now the written record of what
each one enforces. The read routes that had no check at all — `GET /v1/routes`,
`/v1/services`, `/v1/middlewares`, `/v1/tls-options`, `/v1/certs`,
`/v1/entryPoints`, `/v1/traces`, `/v1/cloudflare-ips` — were given the
permission their RPC twin now requires, so the two sides agree.

Two entries are deliberately not `(action, resource)` pairs:

- `permPublic` — `Login`, `Setup`, `IsSetupRequired` are served before
  authentication by the base handler. Denying them here would break first-run
  setup, which is the failure ADR 0005 fixed in the other direction.
- `permAuthenticated` — `ChangePassword` requires a caller but no resource
  permission, because `ApiService` applies self-or-admin itself. A resource
  permission here would stop an operator or viewer changing their own password.

## Consequences

**A new RPC fails closed and fails loudly.** It is denied on every transport
until it is added to the table, and the completeness test fails in CI the moment
the proto changes. This is the property the codebase did not have: the original
defect was invisible precisely because removing a check produced no signal.

**The remaining Connect migration is now safe to finish.** Moving an RPC from
REST to Connect no longer changes who can call it. That was the actual blocker
behind treating the migration as deferrable work — it was not deferring
enforcement, it was removing it — and it is gone.

**Two enforcement points now exist for the same concept.** `RequirePermission`
on REST and `apiPermissions` on the other two can drift: someone can change a
REST route's permission without changing the table. The completeness test
catches a *missing* entry, not a *stale* one. Closing this properly means
deriving both from one declaration, which is a larger refactor deferred here.
Until then, a change to any `RequirePermission` call must be mirrored in
`apiPermissions`, and the table's comments name the REST route each entry came
from so the pairing is checkable by reading.

**`POST /v1/config/validate` became stricter.** It now requires
`ActionWrite`/`ResourceConfig`, matching import rather than export, so a viewer
can no longer submit 5MB of JSON for parsing. This is a deliberate behaviour
change, not a compatibility break we expect anyone to notice.

**Unmapped-denies is a real constraint on the gRPC surface.** Any external gRPC
client calling an RPC absent from the table now receives `PermissionDenied`.
The table covers every RPC `ApiService` declares, so this only bites for
procedures added later without an entry — which is the intent.

**What this does not fix.** `ApiService` still has no authorization of its own
beyond the two user-management checks. If a fourth transport is ever added, it
will need the same interceptor; nothing forces that but this ADR. Moving the
check into the service layer would, and remains the better long-term shape.
