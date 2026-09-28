# 38. Binding a credential-injecting middleware to a route needs an administrator

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary. Attaching a
middleware to a route was an operator's to do; attaching one that delivers a
credential to the backend is now an administrator's, because the operator
chooses the backend.

## Context

ADR 0033 made middleware secrets write-only and ADR 0034 gated their references,
and ADR 0033 recorded one residue it could not close from the middleware store
alone:

> **A credential header or query value goes to the route's backend.** The
> headers and rewrite middlewares send what they set to whatever backend the
> route using them points at, and an operator may write routes and services. So
> an operator can attach an existing headers middleware to a route whose backend
> they run and receive the stored `Authorization` value. Binding it would need
> the route graph (every route using the middleware, and the services behind
> them) checked on every route and service save. Not done here.

That is a full operator-to-administrator escalation, and it survives write-only.
An operator cannot *read* the stored `Authorization: Bearer …` an administrator
configured on a headers middleware (ADR 0033), and cannot make the gateway
*resolve* a reference to exfiltrate it (ADR 0034). But they do not need to. They
can:

- create a service whose target is a backend they control (an operator may write
  services), and a route that points at it and lists the admin's
  credential-injecting middleware; or
- take a route an administrator already built with that middleware and repoint
  it -- either the route's `service_id`, or the target of the service it backs
  -- at a backend they run.

Either way the gateway applies the middleware and forwards the stored credential
to the operator's server, where they read it from the request. The credential
outlives the stolen session; it is the administrator's real secret, not a
placeholder.

The gap is that binding was checked only for the write permission on *routes* or
*services*, never against who may see the credential the binding moves. The two
resources an operator owns compose into one they do not.

`RequirePermission` (REST) and the `apiPermissions` table (Connect/gRPC, ADR
0006/0027) cannot express this: the permission they enforce is `(write, routes)`,
which the operator holds, and neither sees the route's contents or the middleware
it names. The rule is a property of *what the save does*, not of the procedure.

## Decision

**Only an administrator may create or change a route in a way that newly binds a
credential-injecting middleware to it, or repoints a route -- or the service it
backs -- that carries one to a different backend.** An operator keeps every
other power over routes and services.

Precisely, for a caller who is not an administrator (an operator; a viewer never
reaches here, having no write), a save is refused when:

- **A route newly binds a credential-injecting middleware.** The middleware is
  in the route's list now and was not in the stored route's list (a create binds
  all of them). An id present on both is a binding the caller kept, which is
  allowed -- an operator may manage a route an administrator built, priorities,
  rules, entrypoints and all, as long as they do not add such a binding.
- **A route that carries a credential-injecting middleware is repointed.** The
  updated route names one and its `service_id` differs from the stored route's.
  Keeping the binding is allowed; moving the backend under it is not.
- **A service that a credential-carrying route depends on is repointed.** The
  service exists, its targets or discovery URL differ from the stored service's,
  and some route pointing at it lists a credential-injecting middleware. Renaming
  or otherwise editing such a service without changing where it sends traffic is
  allowed; changing the backend is not. A brand-new service has an id no route
  can reference yet, so creating one is never a repoint.

An administrator may do all of it. With authentication off there is no
operator/administrator distinction and the management plane is open by
configuration, so the guard does not restrict -- as `RequirePermission` does not.

**Where it is enforced.** Inside the domain `SaveRoute` and `SaveService`, which
the REST handlers, the Connect/gRPC RPCs and config-import all funnel through.
Enforcing it there, not in a handler, is deliberate: the transport RBAC bypass
(ADR 0006/0027) was a check that lived on one transport and was reached around
by another, and config-import is a third writer that reuses the same domain
saves. One chokepoint covers all three by construction. The guard reads the
caller's role from the request context -- the claims `PasetoAuth` injects, which
every management transport arrives with -- and **fails closed**: a claims value
present but not readable as `*auth.Claims` is treated as a non-admin, so an
unreadable caller cannot bind. The refusal is `403` over REST and
`PermissionDenied` over Connect/gRPC, and a refused save changes nothing (it runs
before the store write). Code: `internal/authz/routebind`.

**What counts as "injects a credential toward the backend"**
(`mwsecret.InjectsCredentialUpstream`): a `headers` middleware that sets or adds
a **request** header under a credential name, or a `rewrite` middleware that adds
a query parameter under one, with a non-empty value -- reusing
`secretmask.IsCredentialName`, the same classifier ADR 0033 masks on. It is read
from the resolved config shape only; whether the value is a literal, an `enc:`
value or a reference does not matter, because all three reach the backend the
same way. The auth, OIDC and forward-auth middlewares send their secret to a
destination the middleware's own config names (introspection URL, issuer,
address), not to the route's backend, and ADR 0033 already binds a kept secret
to that destination, so they are out of scope here.

**Why exactly this rule, and not more or less.** The threat is the operator
receiving a *stored* credential at a backend they choose. The false-positive
cost is refusing an operator managing an ordinary route, which the industry runs
on -- most routes carry no credential middleware, and an operator must keep
managing them. So the rule fires only on the two operations that move a credential
toward a caller-chosen backend (a new binding, a repoint), and is silent on
everything else. Gating the middleware write instead would not help: an operator
who writes the middleware knows the value they typed, so no stored secret leaks;
the leak is in the *binding*, where a value the operator cannot read meets a
backend they can. Gating only the route, and not the service, would leave the
repoint-the-service half of the same escalation open.

## Consequences

- An operator who needs a route to carry an auth-injecting middleware, or to
  repoint one that does, now asks an administrator. Every other route and service
  change an operator makes is unaffected.
- The check reads the middleware store and, for a service repoint, iterates the
  route list once, on the management save path -- never on the request path.
- The rule composes with ADR 0033/0034: the secret is unreadable, its references
  are host-gated, and now the binding that would deliver it is administrator-only.

### Residue, recorded for a decision

- **A credential under a name that gives nothing away.** `IsCredentialName` is
  name-based; a header called `X-Upstream: <token>` or a secret in a body the
  transform middleware writes is not recognised, exactly as ADR 0033 records for
  masking. An operator who binds one is not stopped. The classifier is shared, so
  closing it there closes it here too.
- **Response-direction credential headers.** A `set_response_Authorization` is
  deliberately out of scope: its value travels to the downstream client, not to
  the route's backend, so it is not a credential injected toward a backend the
  operator picks, and blocking it would refuse an operator legitimately setting a
  `Set-Cookie`. A response header does leak to whoever calls the route, but that
  is a different vector (any client of the route, not specifically the operator's
  backend) and is left for a separate decision.
- **The Connect handler does not serve `UpdateRoute`/`UpdateService`** today
  (`api.NewConnectHandler` embeds the unimplemented handler for them), so the
  Connect path answers unimplemented rather than refusing. If it is ever wired to
  serve them it will funnel through the same domain saves and the same guard, so
  no separate check is added.
